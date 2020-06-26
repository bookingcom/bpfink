package e2etests

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
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
	BPFinkBinPath        string
	BPFinkEbpfProgramm   string
	TestRootDir          string
	GenericMonitoringDir string
}

type genericFileLogRecord struct {
	Level   string
	Generic struct {
		Current string
		Next    string
	}
	File        string `json:"file"`
	ProcessName string
	Message     string `json:"message"`
	User        string `json:"user"`
}

type Event struct {
	File    string
	Message string
}

type ProcessHealth int

const (
	DIED ProcessHealth = iota
	WAITING
	HEALTHY
)

func generateConfig(t *testing.T, testRootDir, genericDir string, ebpfProgrammPath string) string {
	tmplt := strings.TrimSpace(`
level = "info"
database = "{{.TestRootDir}}/bpfink.db"
bcc = "{{.EBPfProgrammPath}}"


[consumers]
root = "/"
generic = ["{{.GenericMonitoringDir}}"]
`)

	outConfigPath := path.Join(testRootDir, "agent.toml")
	configFile, err := os.Create(outConfigPath)
	if err != nil {
		t.Fatalf("failed to create config file %s: %s", outConfigPath, err)
	}

	tmpl := template.Must(template.New("config").Parse(tmplt))
	err = tmpl.Execute(configFile, struct {
		TestRootDir          string
		GenericMonitoringDir string
		EBPfProgrammPath     string
	}{testRootDir, genericDir, ebpfProgrammPath})

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

	stdErrLogPath := path.Join(params.TestRootDir, "stderr.log")
	stdErrFile, err := os.OpenFile(stdErrLogPath, os.O_CREATE|os.O_RDWR|os.O_SYNC, 0666)
	if err != nil {
		t.Fatalf("can't init stderr log file %s: %s", stdErrLogPath, err)
	}

	instance := &BPFinkInstance{
		t: t,
	}

	if err := os.MkdirAll(params.TestRootDir, 0700); err != nil {
		t.Fatalf("can't create sandbox dir %s for bpfink: %s", params.TestRootDir, err)
	}

	if err = os.Mkdir(params.GenericMonitoringDir, 0666); err != nil {
		t.Fatalf("unable to create dir for generic monitoring: %s", err)
	}

	configPath := generateConfig(t, params.TestRootDir, params.GenericMonitoringDir, params.BPFinkEbpfProgramm)

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

func (instance *BPFinkInstance) ExpectGenericEvent(t *testing.T, e Event) {
	// give the event time to happen (file sync)
	time.Sleep(10 * time.Millisecond)
	line, err := instance.stdErr.ReadString('\n')
	if err != nil {
		t.Errorf("unable to read line from the file: %s", err)
		return
	}

	var record genericFileLogRecord
	if err = json.Unmarshal([]byte(line), &record); err != nil {
		t.Errorf("unable to parse line [%s] as generic file log record: %s", line, err)
		return
	}

	if record.Level != "warn" {
		t.Errorf("actual record type [%s] is not equal to expected [info]", record.Level)
	}

	if record.File != e.File {
		t.Errorf("actual file record [%s] is not equal to expected [%s]", record.File, e.File)
	}

	if record.Message != e.Message {
		t.Errorf("actual message record [%s] is not equal to expected [%s]", record.Message, e.Message)
	}

	if currentUser, err := user.Current(); err != nil {
		t.Errorf("unable to get current user")
	} else if record.User != currentUser.Username {
		t.Errorf("actual user record [%s] is not equal to expected [%s]", record.User, currentUser.Username)
	}
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
