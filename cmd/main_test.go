package cmd

import (
	"testing"

	"github.com/bookingcom/bpfink/pkg"
)

type watcherTest struct {
	name         string
	action       string
	modification string
	event        pkg.Event
	fixture      string
}

func TestMain(t *testing.T) {
	// cfg := Configuration{

	// }

	// watcher, err := config.watcher()
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// defer func() {
	// 	watcher.Stop()
	// }()
	// go watcher.start()

	// watcherTests := buildWatcherTests()

	// for _, tt := range watcherTests {
	// 	t.Run(tt.name, func(t *testing.T) {

	// 		watcher.Events <- tt.event
	// 	})
	// }
	// watcher.Stop()
}

func buildWatcherTests() []watcherTest {
	watcherTests := []watcherTest{}

	//test for adding to a new line to access.conf
	watcherTests = append(watcherTests, watcherTest{
		name:         "add to access.conf",
		action:       "append",
		modification: "+:nobody:nobody",
		event: pkg.Event{
			Mode:   1,
			PID:    23412,
			UID:    1001,
			Size:   0,
			Inode:  7061877,
			Device: 0,
			Com:    "/bin/sh ./examples/watcher/setup.sh",
			Path:   "access.conf",
		},
		fixture: `{"level":"warn","access":{"grant":["john","nobody"],"deny":["root","ALL"]},"add":{"grant":["nobody"],"deny":[]},"del":{"grant":[],"deny":[]},"processName":"/bin/sh ./examples/watcher/setup.sh ","message":"access entries"}`,
	})

	//test for removing to a new line to access.conf
	watcherTests = append(watcherTests, watcherTest{
		name:         "remove to access.conf",
		action:       "remove",
		modification: "1",
		event: pkg.Event{
			Mode:   2,
			PID:    23489,
			UID:    1001,
			Size:   0,
			Inode:  7061877,
			Device: 0,
			Com:    "sed",
			Path:   "access.conf",
		},
		fixture: `{"level":"warn","access":{"grant":["john"],"deny":["root","ALL"]},"add":{"grant":[],"deny":[]},"del":{"grant":["nobody"],"deny":[]},"processName":"sed","message":"access entries"}`,
	})

	//test for adding to a new line to shadow
	watcherTests = append(watcherTests, watcherTest{
		name:         "add user to shadow file",
		action:       "append",
		modification: "RealUser:badPassword:17597::::::",
		event: pkg.Event{
			Mode:   1,
			PID:    23412,
			UID:    1001,
			Size:   1001,
			Inode:  7061876,
			Device: 0,
			Com:    "/bin/sh ./examples/watcher/setup.sh",
			Path:   "shadow",
		},
		fixture: ``,
	})

	//test for adding to a new line to passwd
	watcherTests = append(watcherTests, watcherTest{
		name:         "add user to passwd file",
		action:       "append",
		modification: "RealUser:x:0:0::/root:/bin/bash",
		event: pkg.Event{
			Mode:   1,
			PID:    23412,
			UID:    1001,
			Size:   0,
			Inode:  7061875,
			Device: 0,
			Com:    "/bin/sh ./examples/watcher/setup.sh",
			Path:   "passwd",
		},
		fixture: `{"level":"warn","users":[{"user":"root","passwd":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXDORm","keys":[]},{"user":"RealUser","passwd":"XXXXXXXword","keys":[]}],"add":[{"user":"RealUser","passwd":"XXXXXXXword","keys":[]}],"del":[],"processName":"/bin/sh ./examples/watcher/setup.sh ","message":"Users Modified"}`,
	})

	//test for adding to a new line to passwd
	watcherTests = append(watcherTests, watcherTest{
		name:         "add service user to passwd file",
		action:       "append",
		modification: "serviceAccount:x:1:1::/:/sbin/nologin",
		event: pkg.Event{
			Mode:   1,
			PID:    23412,
			UID:    1001,
			Size:   0,
			Inode:  7061875,
			Device: 0,
			Com:    "/bin/sh ./examples/watcher/setup.sh",
			Path:   "passwd",
		},
		fixture: ``,
	})

	watcherTests = append(watcherTests, watcherTest{
		name:         "remove service account from passwd",
		action:       "remove",
		modification: "1",
		event: pkg.Event{
			Mode:   2,
			PID:    23493,
			UID:    1001,
			Size:   0,
			Inode:  7061875,
			Device: 0,
			Com:    "sed",
			Path:   "access.conf",
		},
		fixture: ``,
	})

	watcherTests = append(watcherTests, watcherTest{
		name:         "remove realUser account from passwd",
		action:       "remove",
		modification: "1",
		event: pkg.Event{
			Mode:   2,
			PID:    23493,
			UID:    1001,
			Size:   0,
			Inode:  7061875,
			Device: 0,
			Com:    "sed",
			Path:   "access.conf",
		},
		fixture: `{"level":"warn","users":[{"user":"root","passwd":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXDORm","keys":[]}],"add":[],"del":[{"user":"RealUser","passwd":"XXXXXXXword","keys":[]}],"processName":"sed","message":"Users Modified"}`,
	})

	watcherTests = append(watcherTests, watcherTest{
		name:         "remove realUser account from passwd",
		action:       "remove",
		modification: "1",
		event: pkg.Event{
			Mode:   2,
			PID:    23495,
			UID:    1001,
			Size:   0,
			Inode:  7061876,
			Device: 0,
			Com:    "sed",
			Path:   "access.conf",
		},
		fixture: ``,
	})

	return watcherTests
}
