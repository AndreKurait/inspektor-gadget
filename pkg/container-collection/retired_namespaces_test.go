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

package containercollection

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestRetiredNamespacesSurviveRestartsAndAreReleased(t *testing.T) {
	for _, cleanup := range []string{"expiration", "shutdown"} {
		t.Run(cleanup, func(t *testing.T) {
			cc := &ContainerCollection{}
			updater := &fakeTracerMapsUpdater{containers: make(map[string]*Container)}
			require.NoError(t, cc.Initialize(WithTracerCollection(updater)))
			closed := false
			t.Cleanup(func() {
				if !closed {
					cc.Close()
				}
			})
			cc.mu.Lock()
			cc.cacheDelay = time.Hour
			cc.mu.Unlock()

			var incarnations []*Container
			var descriptors []int
			for i := 0; i < 3; i++ {
				c := &Container{
					Runtime: RuntimeMetadata{BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						RuntimeName:   types.RuntimeNameDocker,
						ContainerID:   "restarted-container",
						ContainerName: fmt.Sprintf("incarnation-%d", i),
						ContainerPID:  uint32(os.Getpid()),
					}},
					Mntns: uint64(1000 + i),
					Netns: uint64(2000 + i),
				}
				cc.AddContainer(c)
				require.Same(t, c, cc.GetContainer(c.Runtime.ContainerID))
				fd := c.mntNsFd
				// Clean leaked entries even when exercising an unfixed cache.
				t.Cleanup(func() {
					if lookupContainerByMntns(cc.cachedContainers, c.Mntns) == nil {
						if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
							c.close()
						}
					}
				})
				descriptors = append(descriptors, c.mntNsFd, c.netNsFd)
				incarnations = append(incarnations, c)
				cc.RemoveContainer(c.Runtime.ContainerID)
			}
			for _, c := range incarnations {
				event := &types.CommonData{}
				cc.EnrichByMntNs(event, c.Mntns)
				require.Equal(t, c.Runtime.ContainerName, event.Runtime.ContainerName,
					"each retired incarnation must enrich delayed events during its grace period")
				require.Same(t, c, lookupContainersByNetns(cc.cachedContainers, c.Netns)[0])
			}

			if cleanup == "shutdown" {
				cc.Close()
				closed = true
			} else {
				cc.mu.Lock()
				cc.cacheDelay = 0
				cc.mu.Unlock()
			}
			require.Eventually(t, func() bool {
				for _, fd := range descriptors {
					if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
						return false
					}
				}
				return true
			}, 10*time.Second, 10*time.Millisecond,
				"retired namespace references must not pin removed containers' mounts")
			for _, c := range incarnations {
				require.Nil(t, lookupContainerByMntns(cc.cachedContainers, c.Mntns))
				require.Empty(t, lookupContainersByNetns(cc.cachedContainers, c.Netns))
			}
		})
	}
}
