// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ipam/resynctest"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	instanceCallTimeout      = 2 * time.Second
	instanceCallCleanupLimit = 10 * time.Second
	instanceOverlapWindow    = 500 * time.Millisecond
)

type incrementalTestEC2API struct {
	EC2API
	afterGetInstance func(context.Context, string, *ipamTypes.Instance, error) (*ipamTypes.Instance, error)
}

func (api *incrementalTestEC2API) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance, err := api.EC2API.GetInstance(ctx, vpcs, subnets, instanceID)
	if api.afterGetInstance != nil {
		return api.afterGetInstance(ctx, instanceID, instance, err)
	}
	return instance, err
}

func newIncrementalTestInstances(t *testing.T, afterGetInstance func(context.Context, string, *ipamTypes.Instance, error) (*ipamTypes.Instance, error)) (*InstancesManager, *apiMock.API) {
	t.Helper()

	cloud := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	api := &incrementalTestEC2API{EC2API: cloud, afterGetInstance: afterGetInstance}
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMockapi)
	require.NoError(t, err)
	return instances, cloud
}

func seedIncrementalTestInstances(t *testing.T, instances *InstancesManager, cloud *apiMock.API, instanceIDs ...string) map[string]string {
	t.Helper()

	initialENIs := make(map[string]string, len(instanceIDs))
	for index, instanceID := range instanceIDs {
		eni := createIncrementalTestENI(t, cloud, instanceID, int32(index))
		initialENIs[instanceID] = eni.ID
	}
	_, err := instances.Resync(t.Context())
	require.NoError(t, err)
	return initialENIs
}

func createIncrementalTestENI(t *testing.T, cloud *apiMock.API, instanceID string, index int32) *awsTypes.ENI {
	t.Helper()

	eniID, eni, err := cloud.CreateNetworkInterface(t.Context(), 1, testSubnet.ID, "incremental resync test", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = cloud.AttachNetworkInterface(t.Context(), index, instanceID, eniID)
	require.NoError(t, err)
	eni.ID = eniID
	eni.Number = int(index)
	return eni
}

func gateFirstInstanceSnapshot(instanceID string) (func(context.Context, string, *ipamTypes.Instance, error) (*ipamTypes.Instance, error), <-chan struct{}, func()) {
	snapshotReady := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	var mu lock.Mutex
	held := false
	var releaseOnce sync.Once

	hook := func(ctx context.Context, gotInstanceID string, instance *ipamTypes.Instance, err error) (*ipamTypes.Instance, error) {
		mu.Lock()
		shouldHold := gotInstanceID == instanceID && !held
		if shouldHold {
			held = true
		}
		mu.Unlock()
		if shouldHold {
			close(snapshotReady)
			select {
			case <-releaseSnapshot:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return instance, err
	}
	release := func() { releaseOnce.Do(func() { close(releaseSnapshot) }) }
	return hook, snapshotReady, release
}

type incrementalCall struct {
	done chan struct{}
	err  error
}

func startIncrementalCall(operation func() error) *incrementalCall {
	call := &incrementalCall{done: make(chan struct{})}
	go func() {
		call.err = operation()
		close(call.done)
	}()
	return call
}

func (call *incrementalCall) wait(timeout time.Duration) (error, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-call.done:
		return call.err, true
	case <-timer.C:
		return nil, false
	}
}

func requireIncrementalCall(t *testing.T, call *incrementalCall, operation string) error {
	t.Helper()
	err, completed := call.wait(instanceCallTimeout)
	require.True(t, completed, "%s did not complete within %v", operation, instanceCallTimeout)
	return err
}

func requireIncrementalSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(instanceCallTimeout):
		t.Fatalf("%s did not reach its synchronization point within %v", operation, instanceCallTimeout)
	}
}

func cleanupIncrementalCalls(t *testing.T, release func(), calls ...*incrementalCall) {
	t.Helper()
	t.Cleanup(func() {
		release()
		for _, call := range calls {
			if call == nil {
				continue
			}
			if _, completed := call.wait(instanceCallCleanupLimit); !completed {
				t.Errorf("incremental call did not stop within %v after releasing its API snapshot", instanceCallCleanupLimit)
			}
		}
	})
}

func TestInstanceSyncDoesNotBlockUnrelatedInstanceOrMutation(t *testing.T) {
	const instanceA = "i-incremental-a"
	const instanceB = "i-incremental-b"

	hook, snapshotReady, release := gateFirstInstanceSnapshot(instanceA)
	instances, cloud := newIncrementalTestInstances(t, hook)
	initialENIs := seedIncrementalTestInstances(t, instances, cloud, instanceA, instanceB)

	aCall := startIncrementalCall(func() error {
		_, err := instances.InstanceSync(t.Context(), instanceA)
		return err
	})
	cleanupIncrementalCalls(t, release, aCall)
	requireIncrementalSignal(t, snapshotReady, "instance A GetInstance snapshot")

	bSyncCall := startIncrementalCall(func() error {
		_, err := instances.InstanceSync(t.Context(), instanceB)
		return err
	})
	cleanupIncrementalCalls(t, release, bSyncCall)
	require.NoError(t, requireIncrementalCall(t, bSyncCall, "instance B refresh"))

	newENI := createIncrementalTestENI(t, cloud, instanceB, 1)
	bMutationCall := startIncrementalCall(func() error {
		instances.UpdateENI(instanceB, newENI)
		return nil
	})
	cleanupIncrementalCalls(t, release, bMutationCall)
	_, mutationCompletedBeforeAUnblocked := bMutationCall.wait(instanceCallTimeout)
	release()

	require.NoError(t, requireIncrementalCall(t, aCall, "instance A refresh"))
	require.NoError(t, requireIncrementalCall(t, bMutationCall, "instance B ENI update"))
	require.True(t, instances.HasInstance(instanceA))
	require.ElementsMatch(t, []string{initialENIs[instanceA]}, cachedENIIDs(instances, instanceA))
	require.True(t, instances.HasInstance(instanceB))
	require.ElementsMatch(t, []string{initialENIs[instanceB], newENI.ID}, cachedENIIDs(instances, instanceB))
	require.True(t, mutationCompletedBeforeAUnblocked, "instance B ENI update waited for instance A's held GetInstance response")
}

func TestInstanceSyncPreservesConcurrentCacheChanges(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T, *apiMock.API, string) *awsTypes.ENI
		apply   func(context.Context, *InstancesManager, string, *awsTypes.ENI) error
		deleted bool
	}{
		{
			name: "update-eni",
			setup: func(t *testing.T, cloud *apiMock.API, instanceID string) *awsTypes.ENI {
				return createIncrementalTestENI(t, cloud, instanceID, 1)
			},
			apply: func(_ context.Context, instances *InstancesManager, instanceID string, eni *awsTypes.ENI) error {
				instances.UpdateENI(instanceID, eni)
				return nil
			},
		},
		{
			name: "delete-instance",
			apply: func(_ context.Context, instances *InstancesManager, instanceID string, _ *awsTypes.ENI) error {
				instances.DeleteInstance(instanceID)
				return nil
			},
			deleted: true,
		},
		{
			name: "newer-refresh",
			setup: func(t *testing.T, cloud *apiMock.API, instanceID string) *awsTypes.ENI {
				return createIncrementalTestENI(t, cloud, instanceID, 1)
			},
			apply: func(ctx context.Context, instances *InstancesManager, instanceID string, _ *awsTypes.ENI) error {
				_, err := instances.InstanceSync(ctx, instanceID)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const instanceID = "i-incremental-same-node"
			hook, snapshotReady, release := gateFirstInstanceSnapshot(instanceID)
			instances, cloud := newIncrementalTestInstances(t, hook)
			initialENIs := seedIncrementalTestInstances(t, instances, cloud, instanceID)
			firstCall := startIncrementalCall(func() error {
				_, err := instances.InstanceSync(t.Context(), instanceID)
				return err
			})
			cleanupIncrementalCalls(t, release, firstCall)
			requireIncrementalSignal(t, snapshotReady, "first instance GetInstance snapshot")

			var changedENI *awsTypes.ENI
			if test.setup != nil {
				changedENI = test.setup(t, cloud, instanceID)
			}
			assertChange := func() {
				if test.deleted {
					require.False(t, instances.HasInstance(instanceID))
					return
				}
				require.True(t, instances.HasInstance(instanceID))
				require.NotNil(t, changedENI)
				require.ElementsMatch(t, []string{initialENIs[instanceID], changedENI.ID}, cachedENIIDs(instances, instanceID))
			}
			changeCall := startIncrementalCall(func() error {
				return test.apply(t.Context(), instances, instanceID, changedENI)
			})
			cleanupIncrementalCalls(t, release, changeCall)
			_, changeCompletedBeforeFirstUnblocked := changeCall.wait(instanceOverlapWindow)
			if changeCompletedBeforeFirstUnblocked {
				require.NoError(t, requireIncrementalCall(t, changeCall, test.name))
				assertChange()
			}

			release()
			require.NoError(t, requireIncrementalCall(t, firstCall, "first instance refresh"))
			require.NoError(t, requireIncrementalCall(t, changeCall, test.name))
			assertChange()
		})
	}
}

func TestInstanceSyncReleasesPerInstanceCoordinationAfterGetInstanceError(t *testing.T) {
	tests := []struct {
		name      string
		canceled  bool
		wantError error
	}{
		{name: "api-error", wantError: errors.New("controlled GetInstance error")},
		{name: "canceled-context", canceled: true, wantError: context.Canceled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const instanceID = "i-incremental-error"
			var mu lock.Mutex
			first := true
			hook := func(ctx context.Context, _ string, instance *ipamTypes.Instance, err error) (*ipamTypes.Instance, error) {
				mu.Lock()
				fail := first
				first = false
				mu.Unlock()
				if !fail {
					return instance, err
				}
				if test.canceled {
					return nil, ctx.Err()
				}
				return nil, test.wantError
			}
			instances, cloud := newIncrementalTestInstances(t, hook)
			initialENIs := seedIncrementalTestInstances(t, instances, cloud, instanceID)

			ctx := t.Context()
			if test.canceled {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			_, err := instances.InstanceSync(ctx, instanceID)
			require.ErrorIs(t, err, test.wantError)

			retry := startIncrementalCall(func() error {
				_, err := instances.InstanceSync(t.Context(), instanceID)
				return err
			})
			require.NoError(t, requireIncrementalCall(t, retry, "refresh after GetInstance error"))
			newENI := createIncrementalTestENI(t, cloud, instanceID, 1)
			mutation := startIncrementalCall(func() error {
				instances.UpdateENI(instanceID, newENI)
				return nil
			})
			require.NoError(t, requireIncrementalCall(t, mutation, "ENI update after GetInstance error"))
			require.ElementsMatch(t, []string{initialENIs[instanceID], newENI.ID}, cachedENIIDs(instances, instanceID))
		})
	}
}

func TestEmptyInstanceSyncKeepsConcurrentIPRelease(t *testing.T) {
	const instanceID = "i-testEmptyInstanceSyncKeepsConcurrentIPRelease"

	ec2api := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	hooked := &hookedEC2API{EC2API: ec2api}
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), hooked, metadataMockapi)
	require.NoError(t, err)

	eniID, eni, err := ec2api.CreateNetworkInterface(t.Context(), 4, testSubnet.ID, "desc", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID)
	require.NoError(t, err)
	_, err = instances.Resync(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, eni.Addresses)
	released := eni.Addresses[0].String()

	resynctest.RunDuringFullResync(t,
		func(hook func()) { hooked.afterGetInstances = hook },
		func(ctx context.Context) error {
			_, err := instances.InstanceSync(ctx, "")
			return err
		},
		func() error {
			return ec2api.UnassignPrivateIpAddresses(context.Background(), eniID, []string{released})
		},
		func() {
			instances.RemoveIPsFromENI(instanceID, eniID, []string{released})
		})

	require.NotContains(t, cachedENIAddresses(instances, instanceID), released)
}

func TestUpdateENIDoesNotRecreateDeletedInstance(t *testing.T) {
	const instanceID = "i-incremental-deleted"
	instances, cloud := newIncrementalTestInstances(t, nil)
	seedIncrementalTestInstances(t, instances, cloud, instanceID)

	instances.DeleteInstance(instanceID)
	instances.UpdateENI(instanceID, createIncrementalTestENI(t, cloud, instanceID, 1))
	require.False(t, instances.HasInstance(instanceID))
}
