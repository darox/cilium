// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	agentMetrics "github.com/cilium/cilium/pkg/metrics"
	metricPkg "github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
)

type ownerMock struct{}

func (o *ownerMock) K8sEventReceived(resourceApiGroup, scope string, action string, valid, equal bool) {
}

func (o *ownerMock) K8sEventProcessed(scope string, action string, status bool) {}

func (o *ownerMock) UpdateCiliumNodeResource() {}

type resourceMock struct{}

func (rm *resourceMock) Observe(ctx context.Context, next func(resource.Event[*ciliumv2.CiliumNode]), complete func(error)) {
	<-ctx.Done()
	complete(ctx.Err())
}

func (rm *resourceMock) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*ciliumv2.CiliumNode] {
	return nil
}

func (rm *resourceMock) Store(context.Context) (resource.Store[*ciliumv2.CiliumNode], error) {
	return nil, errors.New("unimplemented")
}

type fakeMTU struct{}

func (f *fakeMTU) GetDeviceMTU() int {
	return 1500
}

func (f *fakeMTU) GetRouteMTU() int {
	return 1500
}

var mtuMock = fakeMTU{}

func TestIPAMLocalStateMetrics(t *testing.T) {
	capacity := metricPkg.NewGaugeVec(metricPkg.GaugeOpts{Name: "test_ipam_capacity"}, []string{agentMetrics.LabelDatapathFamily, agentMetrics.LabelCIDR})
	available := metricPkg.NewGaugeVec(metricPkg.GaugeOpts{Name: "test_ipam_available"}, []string{agentMetrics.LabelDatapathFamily})
	used := metricPkg.NewGaugeVec(metricPkg.GaugeOpts{Name: "test_ipam_used"}, []string{agentMetrics.LabelDatapathFamily})
	attempts := metricPkg.NewCounterVec(metricPkg.CounterOpts{Name: "test_ipam_allocation_attempts_total"}, []string{agentMetrics.LabelDatapathFamily, agentMetrics.LabelOutcome})
	events := metricPkg.NewCounterVec(metricPkg.CounterOpts{Name: "test_ipam_events_total"}, []string{agentMetrics.LabelAction, agentMetrics.LabelDatapathFamily})

	oldCapacity, oldAvailable, oldUsed := agentMetrics.IPAMCapacity, agentMetrics.IPAMAvailable, agentMetrics.IPAMUsed
	oldAttempts, oldEvents := agentMetrics.IPAMAllocationAttempts, agentMetrics.IPAMEvent
	agentMetrics.IPAMCapacity, agentMetrics.IPAMAvailable, agentMetrics.IPAMUsed = capacity, available, used
	agentMetrics.IPAMAllocationAttempts, agentMetrics.IPAMEvent = attempts, events
	t.Cleanup(func() {
		agentMetrics.IPAMCapacity, agentMetrics.IPAMAvailable, agentMetrics.IPAMUsed = oldCapacity, oldAvailable, oldUsed
		agentMetrics.IPAMAllocationAttempts, agentMetrics.IPAMEvent = oldAttempts, oldEvents
	})

	conf := testDaemonConfig()
	store := newFakeNodeStore(conf, t)
	allocator := &crdAllocator{
		logger:    hivetest.Logger(t),
		allocated: ipamTypes.AllocationMap{},
		family:    IPv4,
		store:     store,
		conf:      conf,
	}
	store.allocators = []*crdAllocator{allocator}
	ipam := NewIPAM(NewIPAMParams{Logger: hivetest.Logger(t), AgentConfig: conf})
	ipam.ipv4Allocator = allocator

	first := iputil.AddrFrom(netip.MustParseAddr("10.0.0.1"))
	second := iputil.AddrFrom(netip.MustParseAddr("10.0.0.2"))
	node := newCiliumNode("node1", 0, 0, 0)
	node.Spec.IPAM.Pool = ipamTypes.AllocationMap{first: {}, second: {}}
	store.updateLocalNodeResource(node)

	require.Equal(t, float64(2), capacity.WithLabelValues(string(IPv4), "").Get())
	require.Equal(t, float64(2), available.WithLabelValues(string(IPv4)).Get())
	require.Equal(t, float64(0), used.WithLabelValues(string(IPv4)).Get())

	allocation, err := ipam.AllocateNextFamily(IPv4, "test-owner", PoolDefault())
	require.NoError(t, err)
	require.Equal(t, float64(1), available.WithLabelValues(string(IPv4)).Get())
	require.Equal(t, float64(1), used.WithLabelValues(string(IPv4)).Get())
	require.Equal(t, float64(1), attempts.WithLabelValues(string(IPv4), metricOutcomeSuccess).Get())

	require.NoError(t, ipam.ReleaseIP(allocation.IP, allocation.IPPoolName))
	require.Equal(t, float64(2), available.WithLabelValues(string(IPv4)).Get())
	require.Equal(t, float64(0), used.WithLabelValues(string(IPv4)).Get())
	require.Equal(t, float64(1), events.WithLabelValues(metricRelease, string(IPv4)).Get())

	delete(node.Spec.IPAM.Pool, second)
	store.updateLocalNodeResource(node)
	require.Equal(t, float64(1), capacity.WithLabelValues(string(IPv4), "").Get())
	require.Equal(t, float64(1), available.WithLabelValues(string(IPv4)).Get())

	_, err = ipam.AllocateNextFamily(IPv4, "test-owner", PoolDefault())
	require.NoError(t, err)
	_, err = ipam.AllocateNextFamily(IPv4, "test-owner", PoolDefault())
	require.ErrorIs(t, err, errNoIPsAvailable)
	require.Equal(t, float64(1), attempts.WithLabelValues(string(IPv4), metricOutcomeExhausted).Get())

	ipam.ipv4Allocator = newFakePoolAllocator(map[string]string{"default": "10.1.0.0/30"})
	_, err = ipam.AllocateNextFamily(IPv4, "test-owner", "missing")
	require.Error(t, err)
	require.Equal(t, float64(1), attempts.WithLabelValues(string(IPv4), metricOutcomeOtherError).Get())
}

func TestAllocatedIPDump(t *testing.T) {
	fakeAddressing := fakenode.NewAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    testConfiguration,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
	})
	require.NoError(t, ipam.ConfigureAllocator(t.Context()))

	allocv4, allocv6, status := ipam.Dump()
	require.NotEmpty(t, status)

	// Test the format of the dumped ip addresses
	for ip := range allocv4 {
		require.NotNil(t, net.ParseIP(ip))
	}
	for ip := range allocv6 {
		require.NotNil(t, net.ParseIP(ip))
	}
}

func TestExpirationTimer(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	timeout := 50 * time.Millisecond

	fakeAddressing := fakenode.NewAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    testConfiguration,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
	})
	require.NoError(t, ipam.ConfigureAllocator(t.Context()))

	err := ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NoError(t, err)

	uuid, err := ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NoError(t, err)
	require.NotEmpty(t, uuid)
	// must fail, already registered
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.Error(t, err)
	require.Empty(t, uuid)
	// must fail, already in use
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.Error(t, err)
	// Let expiration timer expire
	time.Sleep(2 * timeout)
	// Must succeed, IP must be released again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NoError(t, err)
	// register new expiration timer
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NoError(t, err)
	require.NotEmpty(t, uuid)
	// attempt to stop with an invalid uuid, must fail
	err = ipam.StopExpirationTimer(ip, PoolDefault(), "unknown-uuid")
	require.Error(t, err)
	// stop expiration with valid uuid
	err = ipam.StopExpirationTimer(ip, PoolDefault(), uuid)
	require.NoError(t, err)
	// Let expiration timer expire
	time.Sleep(2 * timeout)
	// must fail as IP is properly in use now
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.Error(t, err)
	// release IP for real
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.NoError(t, err)

	// allocate IP again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NoError(t, err)
	// register expiration timer
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NoError(t, err)
	require.NotEmpty(t, uuid)
	// release IP, must also stop expiration timer
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.NoError(t, err)
	// allocate same IP again
	err = ipam.AllocateIP(ip, "foo", PoolDefault())
	require.NoError(t, err)
	// register expiration timer must succeed even though stop was never called
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault(), timeout)
	require.NoError(t, err)
	require.NotEmpty(t, uuid)
	// release IP
	err = ipam.ReleaseIP(ip, PoolDefault())
	require.NoError(t, err)
}

func TestAllocateNextWithExpiration(t *testing.T) {
	timeout := 50 * time.Millisecond

	fakeAddressing := fakenode.NewAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	fakeMetadata := fakeMetadataFunc(func(owner string, family Family) (pool string, err error) { return "some-pool", nil })
	ipam := NewIPAM(NewIPAMParams{
		Logger:         hivetest.Logger(t),
		NodeAddressing: fakeAddressing,
		AgentConfig:    testConfiguration,
		NodeDiscovery:  &ownerMock{},
		LocalNodeStore: localNodeStore,
		K8sEventReg:    &ownerMock{},
		NodeResource:   &resourceMock{},
		MTUConfig:      &mtuMock,
		Metadata:       fakeMetadata,
	})
	require.NoError(t, ipam.ConfigureAllocator(t.Context()))

	// Allocate IPs and test expiration timer. 'pool' is empty in order to test
	// that the allocated pool is passed to StartExpirationTimer
	ipv4, ipv6, err := ipam.AllocateNextWithExpiration("", "foo", "", timeout)
	require.NoError(t, err)

	// IPv4 address must be in use
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.Error(t, err)
	// IPv6 address must be in use
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.Error(t, err)

	// Let expiration timer expire
	time.Sleep(time.Second)
	// IPv4 address must be available again
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.NoError(t, err)
	// IPv6 address must be available again
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.NoError(t, err)
	// Release IPs
	err = ipam.ReleaseIP(ipv4.IP, PoolDefault())
	require.NoError(t, err)
	err = ipam.ReleaseIP(ipv6.IP, PoolDefault())
	require.NoError(t, err)

	// Allocate IPs again and test stopping the expiration timer
	ipv4, ipv6, err = ipam.AllocateNextWithExpiration("", "foo", PoolDefault(), timeout)
	require.NoError(t, err)

	// Stop expiration timer for IPv4 address
	err = ipam.StopExpirationTimer(ipv4.IP, PoolDefault(), ipv4.ExpirationUUID)
	require.NoError(t, err)

	// Let expiration timer expire
	time.Sleep(time.Second)
	// IPv4 address must be in use
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault())
	require.Error(t, err)
	// IPv6 address must be available again
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault())
	require.NoError(t, err)
	// Release IPv4 address
	err = ipam.ReleaseIP(ipv4.IP, PoolDefault())
	require.NoError(t, err)
}
