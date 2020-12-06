package main

import (
	"fmt"
	bpfinkCmd "github.com/bookingcom/bpfink/cmd/bpfink"
)

func main() {
	if err := bpfinkCmd.Execute(); err != nil {
		panic(fmt.Sprintf("an error occured while executing to bpfindCmd! Error: %+v", err))
	}
}