// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	"github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/ipam/resynctest"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type hookedInstanceEC2API struct {
	EC2API
	afterGetInstance func()
}

func (h *hookedInstanceEC2API) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance, err := h.EC2API.GetInstance(ctx, vpcs, subnets, instanceID)
	if h.afterGetInstance != nil {
		h.afterGetInstance()
	}
	return instance, err
}

func TestReleaseCIDRsSurvivesInstanceSync(t *testing.T) {
	const instanceID = "i-release-instance-sync"

	ec2api := apiMock.NewAPI([]*ipamTypes.Subnet{testSubnet}, []*ipamTypes.VirtualNetwork{testVpc}, testSecurityGroups, testRouteTables)
	hooked := &hookedInstanceEC2API{EC2API: ec2api}
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), hooked, metadataMockapi)
	require.NoError(t, err)

	eniID, eni, err := ec2api.CreateNetworkInterface(t.Context(), 2, testSubnet.ID, "desc", []string{"sg-1"}, false, false)
	require.NoError(t, err)
	_, err = ec2api.AttachNetworkInterface(t.Context(), 0, instanceID, eniID)
	require.NoError(t, err)
	_, err = instances.Resync(t.Context())
	require.NoError(t, err)
	require.Len(t, eni.Addresses, 2)
	released, retained := eni.Addresses[0].String(), eni.Addresses[1].String()

	node := &Node{
		node:    &mockIPAMNode{instanceID: instanceID},
		manager: instances,
		k8sObj:  newCiliumNode("release-instance-sync", withInstanceID(instanceID)),
	}
	status := &v2.CiliumNode{}
	node.PopulateStatusFields(status)
	require.Equal(t, eni.Addresses, status.Status.ENI.ENIs[eniID].Addresses)
	require.ElementsMatch(t, []string{released, retained}, cachedENIAddresses(instances, instanceID))

	releasedCIDR := netip.PrefixFrom(eni.Addresses[0].Addr, eni.Addresses[0].BitLen())
	var releasedCIDRs []netip.Prefix
	var releaseErr error
	resynctest.RunDuringFullResync(t,
		func(hook func()) { hooked.afterGetInstance = hook },
		func(ctx context.Context) error {
			_, err := instances.InstanceSync(ctx, instanceID)
			return err
		},
		func() error { return nil },
		func() {
			releasedCIDRs, releaseErr = node.ReleaseCIDRs(context.Background(), &nodemanager.ReleaseAction{
				InterfaceID:    eniID,
				CIDRsToRelease: []netip.Prefix{releasedCIDR},
			})
		})
	require.NoError(t, releaseErr)
	require.Equal(t, []netip.Prefix{releasedCIDR}, releasedCIDRs)

	cloud, err := ec2api.GetInstance(t.Context(), nil, nil, instanceID)
	require.NoError(t, err)
	require.Equal(t, eni.Addresses[1:], cloud.Interfaces[eniID].(*types.ENI).Addresses)
	assert.Equal(t, []string{retained}, cachedENIAddresses(instances, instanceID))
	node.PopulateStatusFields(status)
	assert.Equal(t, eni.Addresses[1:], status.Status.ENI.ENIs[eniID].Addresses)
}
