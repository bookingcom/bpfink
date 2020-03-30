#!/bin/sh
cd "$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)" || exit 1
PROJECT="$(realpath ../..)"

_access() {
  cat >bpfink.access <<-EOF
		-:root:ALL
		#
		# User "foo" and members of netgroup "nis_group" should be
		# allowed to get access from all sources.
		# This will only work if netgroup service is available.
		#
		# User "john" should get access from ipv4 net/mask
		+:john:127.0.0.0/24
		#
		# User "john" should get access from ipv4 as ipv6 net/mask
		#+:john:::ffff:127.0.0.0/127
		#
		# User "john" should get access from ipv6 host address
		#+:john:2001:4ca0:0:101::1
		#
		# User "john" should get access from ipv6 host address (same as above)
		#+:john:2001:4ca0:0:101:0:0:0:1
		#
		# User "john" should get access from ipv6 net/mask
		#+:john:2001:4ca0:0:101::/64
		#
		# All other users should be denied to get access from all sources.
		-:ALL:ALL
	EOF
}

_passwd() {
  cat >bpfink.passwd <<-EOF
		root:x:0:0::/root:/bin/bash
		bin:x:1:1::/:/sbin/nologin
		daemon:x:2:2::/:/sbin/nologin
	EOF
}

_shadow() {
  cat >bpfink.shadow <<-'EOF'
		root:$2y$05$67G8sQFkJR3j1JpWj71f5e29UBxuBk7WSr3Og7yUTX1wEJBWcDORm:17597::::::
	EOF
}

_sudoers () {
	cat > bpfink.sudoers <<- EOF
		root ALL = (ALL:ALL) ALL
	EOF
}

_config () {
	echo "bcc = \"${PROJECT}/pkg/ebpf/vfs.o\"" >> bpfink.toml
	echo "keyfile = \"\"" >> bpfink.toml
	cat >> bpfink.toml <<- 'EOF'
		level = "debug"
		database = "bpfink.db"
		[consumers]
	EOF
  echo "root = \"/\"" >>bpfink.toml

  echo "access = \"${PROJECT}/examples/watcher/test-dir/bpfink.access\"" >> bpfink.toml
  echo "generic = [\"${PROJECT}/examples/watcher/test-dir/dynamic-watcher\", \"/etc\"]" >> bpfink.toml
  echo "sudoers = \"${PROJECT}/examples/watcher/test-dir/bpfink.sudoers\"" >> bpfink.toml
  cat >> bpfink.toml <<- 'EOF'

		[consumers.users]
	EOF
  echo "passwd = \"${PROJECT}/examples/watcher/test-dir/bpfink.passwd\"" >>bpfink.toml
  echo "shadow = \"${PROJECT}/examples/watcher/test-dir/bpfink.shadow\"" >>bpfink.toml
  cat >>bpfink.toml <<-'EOF'
		[MetricsConfig]
		graphiteHost = "127.0.0.1:3002"
		namespace = ""
		graphiteMode = "1" #1 = no logs 2 = stdout 3 = graphite server
		collectionInterval = "30s" # Seconds
		hostRolePath = "" # Path to file to identify server type
		hostRoleToken = ""
		hostRoleKey = "" # Key to look for in file

	EOF
}

init() {
  mkdir test-dir
  cd test-dir || exit
  mkdir -p dynamic-watcher/dir-test
  touch dynamic-watcher/testFile
  touch dynamic-watcher/dir-test/example.txt
  cd dynamic-watcher || exit
  ln -s dir-test/example.txt linked_text
  cd ..
  _passwd
  _shadow
  _access
  _config
  make -r -C "${PROJECT}/pkg/ebpf" || exit
}

run_test() {
  printf "\n\nwaiting for bpfink to start\n\n"
  sleep 7

  ##Access
  printf "\n\nadding '+:nobody:nobody' to bpfink.access\n"
  echo "+:nobody:nobody" >>bpfink.access
  sleep 2
  printf "\n\nremove last addition\n"
  sed -i '$ d' bpfink.access
  sleep 2

  ##Shadow
  printf "\n\nadding 'RealUser:badPassword:17597::::::' to bpfink.shadow\n"
  echo "RealUser:badPassword:17597::::::" >>bpfink.shadow
  sleep 2

  ##Passwd
  printf "\n\nadding 'RealUser:x:0:0::/root:/bin/bash' and 'serviceAccount:x:1:1::/:/sbin/nologin' to bpfink.passwd\n\n"
  echo "RealUser:x:4:4::/root:/bin/bash" >>bpfink.passwd
  echo "serviceAccount:x:3:3::/:/sbin/nologin" >>bpfink.passwd
  sleep 2
  printf "\n\ncleaning up bpfink.showdow and bpfink.passwd\n\n"
  sed -i '$ d' bpfink.passwd
  sed -i '$ d' bpfink.passwd
  sed -i '$ d' bpfink.shadow
  sleep 2

  printf "\n\ncreate a new file in dynamic-watcher\n\n"
  echo "Real Time file creation" >>dynamic-watcher/dynamic-file.txt
  sleep 2

  printf "\n\nwrite to sym linked file\n\n"
  echo "symlink file write" >>dynamic-watcher/linked_text
  sleep 2

  printf "\n\ncreate a new dir in dynamic-watcher\n\n"
  mkdir dynamic-watcher/realtimePath
  sleep 2

  printf "\n\ncreate a new file in the newly created in dynamic-watcher\n\n"
  touch dynamic-watcher/realtimePath/dynamicPathFile
  sleep 2

  ##Future examples

  ##Wrap up
  printf "\n\nGuided examples now over. Feel free to try modifying the above example files your self\n"
  printf "all monitored files can be found in test-dir, which will be cleaned up when stopping this process\n"
  printf "To quit use ctrl c\n\n"
}

run() {
  clean
  init
  run_test &
  sudo go run "${PROJECT}"/cmd/main.go --config "${PROJECT}"/examples/watcher/test-dir/bpfink.toml
  clean
}

clean() {
  rm -rf test-dir/
  rm -rf bpfink.*
}

run
