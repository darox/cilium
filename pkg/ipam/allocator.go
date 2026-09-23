// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/sets"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const (
	metricAllocate          = "allocate"
	metricRelease           = "release"
	metricOutcomeSuccess    = "success"
	metricOutcomeExhausted  = "exhausted"
	metricOutcomeOtherError = "error"
)

// Error definitions
var (
	// ErrIPv4Disabled is returned when IPv4 allocation is disabled
	ErrIPv4Disabled = errors.New("IPv4 allocation disabled")

	// ErrIPv6Disabled is returned when Ipv6 allocation is disabled
	ErrIPv6Disabled = errors.New("IPv6 allocation disabled")

	// ErrRoutingMetadataUnsupported is returned when an allocator cannot
	// resolve routing metadata for a given address.
	ErrRoutingMetadataUnsupported = errors.New("routing metadata lookup unsupported")
)

type routingMetadataResolver interface {
	ResolveRoutingMetadata(addr netip.Addr, pool Pool) (*AllocationResult, error)
}

func updateIPAMMetrics(family Family, allocator Allocator, cidr string) {
	stats := allocator.Stats()
	metrics.IPAMCapacity.WithLabelValues(string(family), cidr).Set(float64(stats.Capacity))
	metrics.IPAMAvailable.WithLabelValues(string(family)).Set(float64(stats.Available))
	metrics.IPAMUsed.WithLabelValues(string(family)).Set(float64(stats.Used))
}

func (ipam *IPAM) updateIPAMMetrics(family Family, allocator Allocator) {
	var cidr string
	if ipam.config.IPAMMode() == ipamOption.IPAMClusterPool || ipam.config.IPAMMode() == ipamOption.IPAMKubernetes {
		if family == IPv4 {
			cidr = ipam.nodeAddressing.IPv4().AllocationCIDR().String()
		} else {
			cidr = ipam.nodeAddressing.IPv6().AllocationCIDR().String()
		}
	}
	updateIPAMMetrics(family, allocator, cidr)
}

func allocationOutcome(err error) string {
	switch {
	case err == nil:
		return metricOutcomeSuccess
	case errors.Is(err, ipallocator.ErrFull),
		errors.Is(err, errAllCIDRsExhausted),
		errors.Is(err, errNoIPsAvailable),
		errors.Is(err, &ErrPoolNotReadyYet{}):
		return metricOutcomeExhausted
	default:
		return metricOutcomeOtherError
	}
}

func (ipam *IPAM) determineIPAMPool(owner string, family Family) (Pool, error) {
	pool, err := ipam.metadata.GetIPPoolForPod(owner, family)
	if err != nil {
		return "", fmt.Errorf("unable to determine IPAM pool for owner %q: %w", owner, err)
	}

	return Pool(pool), nil
}

// AllocateIP allocates an IP address.
func (ipam *IPAM) AllocateIP(ip netip.Addr, owner string, pool Pool) error {
	needSyncUpstream := true
	_, err := ipam.allocateIP(ip, owner, pool, needSyncUpstream)
	return err
}

// AllocateIPWithoutSyncUpstream allocates an IP address without syncing upstream.
func (ipam *IPAM) AllocateIPWithoutSyncUpstream(ip netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	needSyncUpstream := false
	return ipam.allocateIP(ip, owner, pool, needSyncUpstream)
}

// ResolveRoutingMetadata returns the routing metadata for an address without
// changing its allocation or synchronizing any state upstream.
func (ipam *IPAM) ResolveRoutingMetadata(addr netip.Addr, pool Pool) (*AllocationResult, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid IP address: %v", addr)
	}
	addr = addr.Unmap()

	ipam.allocatorMutex.RLock()
	resolver := ipam.ipv6RoutingMetadataResolver
	if addr.Is4() {
		resolver = ipam.ipv4RoutingMetadataResolver
	}
	ipam.allocatorMutex.RUnlock()

	if resolver == nil {
		return nil, ErrRoutingMetadataUnsupported
	}
	return resolver.ResolveRoutingMetadata(addr, PoolOrDefault(string(pool)))
}

// AllocateIPString is identical to AllocateIP but takes a string
func (ipam *IPAM) AllocateIPString(ipAddr, owner string, pool Pool) error {
	addr, err := netip.ParseAddr(ipAddr)
	if err != nil {
		return fmt.Errorf("Invalid IP address: %s", ipAddr)
	}
	return ipam.AllocateIP(addr, owner, pool)
}

func (ipam *IPAM) allocateIP(ip netip.Addr, owner string, pool Pool, needSyncUpstream bool) (result *AllocationResult, err error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	if pool == "" {
		return nil, fmt.Errorf("unable to restore IP %s for %q: pool name must be provided", ip, owner)
	}

	if !ip.IsValid() {
		return nil, fmt.Errorf("invalid IP address: %v", ip)
	}

	if ownedBy, ok := ipam.isIPExcluded(ip, pool); ok {
		err = fmt.Errorf("IP %s is excluded, owned by %s", ip, ownedBy)
		return
	}

	family := IPv4
	var allocator Allocator
	if ip.Is4() {
		allocator = ipam.ipv4Allocator
		if allocator == nil {
			err = ErrIPv4Disabled
			return
		}

		if needSyncUpstream {
			if result, err = allocator.Allocate(ip, owner, pool); err != nil {
				return
			}
		} else {
			if result, err = allocator.AllocateWithoutSyncUpstream(ip, owner, pool); err != nil {
				return
			}
		}
	} else {
		family = IPv6
		allocator = ipam.ipv6Allocator
		if allocator == nil {
			err = ErrIPv6Disabled
			return
		}

		if needSyncUpstream {
			if result, err = allocator.Allocate(ip, owner, pool); err != nil {
				return
			}
		} else {
			if result, err = allocator.AllocateWithoutSyncUpstream(ip, owner, pool); err != nil {
				return
			}
		}
	}
	ipam.updateIPAMMetrics(family, allocator)

	// If the allocator did not populate the pool, we assume it does not
	// support IPAM pools and assign the default pool instead
	if result.IPPoolName == "" {
		result.IPPoolName = PoolDefault()
	}

	ipam.logger.Debug(
		"Allocated specific IP",
		logfields.IPAddr, ip,
		logfields.Owner, owner,
		logfields.PoolName, result.IPPoolName,
	)

	ipam.registerIPOwner(ip, owner, pool)
	metrics.IPAMEvent.WithLabelValues(metricAllocate, string(family)).Inc()
	return
}

func (ipam *IPAM) allocateNextFamily(family Family, owner string, pool Pool, needSyncUpstream bool) (result *AllocationResult, err error) {
	var allocator Allocator
	switch family {
	case IPv6:
		allocator = ipam.ipv6Allocator
	case IPv4:
		allocator = ipam.ipv4Allocator

	default:
		err = fmt.Errorf("unknown address \"%s\" family requested", family)
		return
	}

	if allocator == nil {
		err = fmt.Errorf("%s allocator not available", family)
		return
	}
	defer func() {
		ipam.updateIPAMMetrics(family, allocator)
		metrics.IPAMAllocationAttempts.WithLabelValues(string(family), allocationOutcome(err)).Inc()
	}()

	if pool == "" {
		pool, err = ipam.determineIPAMPool(owner, family)
		if err != nil {
			return
		}
	}

	for {
		if needSyncUpstream {
			result, err = allocator.AllocateNext(owner, pool)
		} else {
			result, err = allocator.AllocateNextWithoutSyncUpstream(owner, pool)
		}
		if err != nil {
			return
		}

		// If the allocator did not populate the pool, we assume it does not
		// support IPAM pools and assign the default pool instead
		if result.IPPoolName == "" {
			result.IPPoolName = PoolDefault()
		}

		resultIP := result.IP
		if _, ok := ipam.isIPExcluded(resultIP, pool); !ok {
			ipam.logger.Debug(
				"Allocated random IP",
				logfields.IPAddr, result.IP,
				logfields.PoolName, result.IPPoolName,
				logfields.Owner, owner,
			)
			ipam.registerIPOwner(resultIP, owner, pool)
			metrics.IPAMEvent.WithLabelValues(metricAllocate, string(family)).Inc()
			return
		}

		// The allocated IP is excluded, do not use it. The excluded IP
		// is now allocated so it won't be allocated in the next
		// iteration.
		ipam.registerIPOwner(resultIP, fmt.Sprintf("%s (excluded)", owner), pool)
	}
}

// AllocateNextFamily allocates the next IP of the requested address family
func (ipam *IPAM) AllocateNextFamily(family Family, owner string, pool Pool) (result *AllocationResult, err error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	needSyncUpstream := true

	return ipam.allocateNextFamily(family, owner, pool, needSyncUpstream)
}

// AllocateNextFamilyWithoutSyncUpstream allocates the next IP of the requested address family
// without syncing upstream
func (ipam *IPAM) AllocateNextFamilyWithoutSyncUpstream(family Family, owner string, pool Pool) (result *AllocationResult, err error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	needSyncUpstream := false

	return ipam.allocateNextFamily(family, owner, pool, needSyncUpstream)
}

// AllocateNext allocates the next available IPv4 and IPv6 address out of the
// configured address pool. If family is set to "ipv4" or "ipv6", then
// allocation is limited to the specified address family. If the pool has been
// drained of addresses, an error will be returned.
func (ipam *IPAM) AllocateNext(family, owner string, pool Pool) (ipv4Result, ipv6Result *AllocationResult, err error) {
	if (family == "ipv6" || family == "") && ipam.ipv6Allocator != nil {
		ipv6Result, err = ipam.AllocateNextFamily(IPv6, owner, pool)
		if err != nil {
			return
		}

	}

	if (family == "ipv4" || family == "") && ipam.ipv4Allocator != nil {
		ipv4Result, err = ipam.AllocateNextFamily(IPv4, owner, pool)
		if err != nil {
			if ipv6Result != nil {
				ipam.ReleaseIP(ipv6Result.IP, ipv6Result.IPPoolName)
			}
			return
		}
	}

	return
}

// AllocateNextWithExpiration is identical to AllocateNext but registers an
// expiration timer as well. This is identical to using AllocateNext() in
// combination with StartExpirationTimer()
func (ipam *IPAM) AllocateNextWithExpiration(family, owner string, pool Pool, timeout time.Duration) (ipv4Result, ipv6Result *AllocationResult, err error) {
	ipv4Result, ipv6Result, err = ipam.AllocateNext(family, owner, pool)
	if err != nil {
		return nil, nil, err
	}

	if timeout != time.Duration(0) {
		for _, result := range []*AllocationResult{ipv4Result, ipv6Result} {
			if result != nil {
				result.ExpirationUUID, err = ipam.StartExpirationTimer(result.IP, result.IPPoolName, timeout)
				if err != nil {
					if ipv4Result != nil {
						ipam.ReleaseIP(ipv4Result.IP, ipv4Result.IPPoolName)
					}
					if ipv6Result != nil {
						ipam.ReleaseIP(ipv6Result.IP, ipv6Result.IPPoolName)
					}
					return
				}
			}
		}
	}

	return
}

func (ipam *IPAM) releaseIPLocked(ip netip.Addr, pool Pool) error {
	if pool == "" {
		return fmt.Errorf("no IPAM pool provided for IP release of %s", ip)
	}

	if !ip.IsValid() {
		return fmt.Errorf("invalid IP address: %v", ip)
	}

	family := IPv4
	var allocator Allocator
	if ip.Is4() {
		allocator = ipam.ipv4Allocator
		if allocator == nil {
			return ErrIPv4Disabled
		}

		allocator.Release(ip, pool)
	} else {
		family = IPv6
		allocator = ipam.ipv6Allocator
		if allocator == nil {
			return ErrIPv6Disabled
		}

		allocator.Release(ip, pool)
	}
	ipam.updateIPAMMetrics(family, allocator)

	owner := ipam.releaseIPOwner(ip, pool)
	ipam.logger.Debug(
		"Released IP",
		logfields.IPAddr, ip,
		logfields.Owner, owner,
	)

	key := poolIP{ip: ip, pool: pool}
	if t, ok := ipam.expirationTimers[key]; ok {
		close(t.stop)
		delete(ipam.expirationTimers, key)
	}

	metrics.IPAMEvent.WithLabelValues(metricRelease, string(family)).Inc()
	return nil
}

// ReleaseIP releases an IP address. The pool argument must not be empty, it
// must be set to the pool name returned by the `Allocate*` functions when
// the IP was allocated.
func (ipam *IPAM) ReleaseIP(ip netip.Addr, pool Pool) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()
	return ipam.releaseIPLocked(ip, pool)
}

// Dump dumps the list of allocated IP addresses
func (ipam *IPAM) Dump() (allocv4 map[string]string, allocv6 map[string]string, status string) {
	var st4, st6 string
	var allocPerPool4, allocPerPool6 map[Pool]sets.Set[netip.Addr]

	allocv4 = make(map[string]string)
	allocv6 = make(map[string]string)

	ipam.allocatorMutex.RLock()
	defer ipam.allocatorMutex.RUnlock()

	if ipam.ipv4Allocator != nil {
		allocPerPool4, st4 = ipam.ipv4Allocator.Dump()
		st4 = "IPv4: " + st4
		for pool, alloc := range allocPerPool4 {
			for addr := range alloc {
				// If owner is not available, report IP but leave owner empty
				allocv4[poolIP{ip: addr, pool: pool}.String()] = ipam.getIPOwner(addr, pool)
			}
		}
	}

	if ipam.ipv6Allocator != nil {
		allocPerPool6, st6 = ipam.ipv6Allocator.Dump()
		st6 = "IPv6: " + st6
		for pool, alloc := range allocPerPool6 {
			for addr := range alloc {
				// If owner is not available, report IP but leave owner empty
				allocv6[poolIP{ip: addr, pool: pool}.String()] = ipam.getIPOwner(addr, pool)
			}
		}
	}

	status = strings.Join([]string{st4, st6}, ", ")
	if status == "" {
		status = "Not running"
	}

	return
}

// StartExpirationTimer installs an expiration timer for a previously allocated
// IP. Unless StopExpirationTimer is called in time, the IP will be released
// again after expiration of the specified timeout. The function will return a
// UUID representing the unique allocation attempt. The same UUID must be
// passed into StopExpirationTimer again.
//
// This function is to be used as allocation and use of an IP can be controlled
// by an external entity and that external entity can disappear. Therefore such
// users should register an expiration timer before returning the IP and then
// stop the expiration timer when the IP has been used.
func (ipam *IPAM) StartExpirationTimer(ip netip.Addr, pool Pool, timeout time.Duration) (string, error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	key := poolIP{ip: ip, pool: pool}
	if _, ok := ipam.expirationTimers[key]; ok {
		return "", fmt.Errorf("expiration timer already registered")
	}

	allocationUUID := uuid.New().String()
	stop := make(chan struct{})
	ipam.expirationTimers[key] = expirationTimer{
		uuid: allocationUUID,
		stop: stop,
	}

	go func(key poolIP, allocationUUID string, timeout time.Duration, stop <-chan struct{}) {
		timer := time.NewTimerWithoutMaxDelay(timeout)
		select {
		case <-stop:
			// Expiration timer was explicitly stopped before timeout.
			// Ensure time.Timer can be garbage collected and exit
			timer.Stop()
			return
		case <-timer.C:
		}

		ipam.allocatorMutex.Lock()
		defer ipam.allocatorMutex.Unlock()

		if t, ok := ipam.expirationTimers[key]; ok {
			if t.uuid == allocationUUID {
				if err := ipam.releaseIPLocked(key.ip, key.pool); err != nil {
					ipam.logger.Warn(
						"Unable to release IP after expiration",
						logfields.Error, err,
						logfields.IPAddr, key.ip,
						logfields.PoolName, key.pool,
						logfields.UUID, allocationUUID,
					)
				} else {
					ipam.logger.Warn(
						"Released IP after expiration",
						logfields.IPAddr, key.ip,
						logfields.PoolName, key.pool,
						logfields.UUID, allocationUUID,
					)
				}
			} else {
				// This is an obsolete expiration timer. The IP
				// was reused and a new expiration timer is
				// already attached
			}
		} else {
			// Expiration timer was removed. No action is required
		}
	}(key, allocationUUID, timeout, stop)

	return allocationUUID, nil
}

// StopExpirationTimer will remove the expiration timer for a particular IP.
// The UUID returned by the symmetric StartExpirationTimer must be provided.
// The expiration timer will only be removed if the UUIDs match. Releasing an
// IP will also stop the expiration timer.
func (ipam *IPAM) StopExpirationTimer(ip netip.Addr, pool Pool, allocationUUID string) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	key := poolIP{ip: ip, pool: pool}
	t, ok := ipam.expirationTimers[key]
	if !ok {
		return fmt.Errorf("no expiration timer registered")
	} else if t.uuid != allocationUUID {
		return fmt.Errorf("UUID mismatch, not stopping expiration timer")
	}

	close(t.stop)
	delete(ipam.expirationTimers, key)

	return nil
}
