// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

func TestTraceTcpFastConnectCompletesOnce(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	for name, family := range map[string]int{
		"ipv4":             unix.AF_INET,
		"ipv4_mapped_ipv6": unix.AF_INET6,
	} {
		t.Run(name, func(t *testing.T) {
			runner := utils.NewRunnerWithTest(t, &utils.RunnerConfig{})
			filter, err := ebpf.NewMap(&ebpf.MapSpec{
				Type: ebpf.Hash, KeySize: 8, ValueSize: 4, MaxEntries: 1,
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, filter.Close()) })
			require.NoError(t, filter.Put(runner.Info.MountNsID, uint32(1)))
			var sourcePorts []int
			var destinationPort int
			trace := gadgetrunner.NewGadgetRunner(t, gadgetrunner.GadgetRunnerOpts[ExpectedTraceTcpEvent]{
				Image:          "trace_tcp",
				Timeout:        5 * time.Second,
				MntnsFilterMap: filter,
				OnGadgetRun: func(operators.GadgetContext) error {
					utils.RunWithRunner(t, runner, func() error {
						var err error
						sourcePorts, destinationPort, err = fastLocalConnections(family, 32)
						return err
					})
					return nil
				},
			})
			trace.RunGadget()
			require.Len(t, sourcePorts, 32, "all connections must complete")

			counts := make(map[int]int)
			for _, event := range trace.CapturedEvents {
				if event.Type != "connect" || int(event.Proc.Tid) != runner.Info.Tid ||
					event.NetNsId != int(runner.Info.NetworkNsID) || int(event.Dst.Port) != destinationPort {
					continue
				}
				require.Empty(t, event.Error)
				counts[int(event.Src.Port)]++
			}
			require.Len(t, counts, len(sourcePorts), "every socket must produce a connect event")
			for _, port := range sourcePorts {
				require.Equal(t, 1, counts[port], "socket with source port %d completed more or less than once", port)
			}
		})
	}
}

// Complete handshakes on loopback before closing each socket. IPv4-mapped IPv6
// sockets exercise both connect return probes while retaining one socket owner.
func fastLocalConnections(family, count int) ([]int, int, error) {
	listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	defer unix.Close(listener)
	if err := unix.Bind(listener, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return nil, 0, err
	}
	if err := unix.Listen(listener, count); err != nil {
		return nil, 0, err
	}
	address, err := unix.Getsockname(listener)
	if err != nil {
		return nil, 0, err
	}
	port := address.(*unix.SockaddrInet4).Port
	ports := make([]int, 0, count)
	for range count {
		sourcePort, err := func() (int, error) {
			client, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return 0, err
			}
			defer unix.Close(client)
			var destination unix.Sockaddr = &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
			if family == unix.AF_INET6 {
				destination = &unix.SockaddrInet6{
					Port: port,
					Addr: [16]byte{10: 0xff, 11: 0xff, 12: 127, 15: 1},
				}
			}
			if err := unix.Connect(client, destination); err != nil {
				return 0, err
			}
			accepted, _, err := unix.Accept(listener)
			if err != nil {
				return 0, err
			}
			defer unix.Close(accepted)
			local, err := unix.Getsockname(client)
			if err != nil {
				return 0, err
			}
			switch local := local.(type) {
			case *unix.SockaddrInet4:
				return local.Port, nil
			case *unix.SockaddrInet6:
				return local.Port, nil
			default:
				return 0, fmt.Errorf("unexpected local address %T", local)
			}
		}()
		if err != nil {
			return nil, port, err
		}
		ports = append(ports, sourcePort)
	}
	return ports, port, nil
}
