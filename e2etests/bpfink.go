package e2etests

import (
	"bufio"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"testing"
	"text/template"
	"time"
)

type BPFinkInstance struct {
	cmd    *exec.Cmd
	stdErr *bufio.Reader
	t      *testing.T
}

type BPFinkRunParameters struct {
	BPFinkBinPath      string
	BPFinkEbpfProgramm string
	SandboxDir         string
}

type ProcessHealth int

const (
	DIED ProcessHealth = iota
	WAITING
	HEALTHY
)

func generateConfig(t *testing.T, rootDir string, ebpfProgrammPath string) string {
	tmplt := strings.TrimSpace(`
level = "info"
database = "{{.Root}}/bpfink.db"
bcc = "{{.EBPfProgrammPath}}"


[consumers]
root = "/"
generic = ["{{.Root}}"]
`)

	outConfigPath := path.Join(rootDir, "agent.toml")
	configFile, err := os.Create(outConfigPath)
	if err != nil {
		t.Fatalf("failed to create config file %s: %s", outConfigPath, err)
	}

	tmpl := template.Must(template.New("config").Parse(tmplt))
	err = tmpl.Execute(configFile, struct {
		Root             string
		EBPfProgrammPath string
	}{rootDir, ebpfProgrammPath})

	if err != nil {
		t.Fatalf("failed to generate config file %s: %s", outConfigPath, err)
	}

	return outConfigPath
}

func BPFinkRun(t *testing.T, params BPFinkRunParameters) *BPFinkInstance {
	if len(params.BPFinkBinPath) == 0 {
		t.Fatal("bpfink binary ABSOLUTE path not specified, specify it through bpfink-bin arg")
	}

	if len(params.BPFinkEbpfProgramm) == 0 {
		t.Fatal("bpfink ebpf programm ABSOLUTE path not specified, specify it through ebpf-obj arg")
	}

	stdErrLogPath := path.Join(params.SandboxDir, "stderr.log")
	stdErrFile, err := os.OpenFile(stdErrLogPath, os.O_CREATE|os.O_RDWR|os.O_SYNC, 0666)
	if err != nil {
		t.Fatalf("can't init stderr log file %s: %s", stdErrLogPath, err)
	}

	instance := &BPFinkInstance{
		t: t,
	}

	if err := os.MkdirAll(params.SandboxDir, 0700); err != nil {
		t.Fatalf("can't create sandbox dir %s for bpfink: %s", params.SandboxDir, err)
	}

	configPath := generateConfig(t, params.SandboxDir, params.BPFinkEbpfProgramm)

	instance.cmd = exec.Command( //nolint:gosec
		params.BPFinkBinPath,
		"--config",
		configPath,
	)

	instance.cmd.Stderr = stdErrFile

	stdErrReader, err := os.OpenFile(stdErrLogPath, os.O_RDONLY, 0666)
	if err != nil {
		t.Fatalf("unable to open stderr log file %s: %s", stdErrLogPath, err)
	}

	instance.stdErr = bufio.NewReader(stdErrReader)

	if err := instance.cmd.Start(); err != nil {
		t.Fatal("Can't create bpfink process: ", err)
	}

	timeout := time.After(10 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-timeout:
			t.Errorf("bpfink doesn't get alive in 10 seconds. stderr log:\n %s", stdErrLogPath)
			return instance
		case <-tick.C:
			switch status := instance.CheckIsHealthy(t); status {
			case DIED:
				t.Errorf("bpfink died at startup.\nstderr log: %s", stdErrLogPath)
				return instance
			case HEALTHY:
				return instance
			}
		}
	}
}

func (instance *BPFinkInstance) CheckIsHealthy(t *testing.T) ProcessHealth {
	var err error
	if err = instance.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Errorf("healthcheck: bpfink process doesn't exist: %s", err)
		return DIED
	}

	line, err := instance.stdErr.ReadString('\n')
	if err != nil {
		return WAITING
	}

	if strings.Contains(line, "bpfink initialized:") {
		return HEALTHY
	}

	return WAITING
}

func (instance *BPFinkInstance) Shutdown() {
	done := make(chan error)
	go func() { done <- instance.cmd.Wait() }()
	timeToDie := 5 * time.Second

	if err := instance.cmd.Process.Signal(os.Interrupt); err != nil {
		instance.t.Fatalf("can't send sigint to bpfink (pid %d) process: %s", instance.cmd.Process.Pid, err)
	}
	select {
	case <-time.After(5 * time.Second):
		err := instance.cmd.Process.Kill()
		instance.t.Errorf("bpfink did not stop gracefully after %s. kill result: %s.", timeToDie, err)
	case err := <-done:
		if err != nil {
			instance.t.Errorf("bpfink stop the work with the error status: %v", err)
			_ = instance.cmd.Process.Kill()
		}
	}
}
