// +build linux

package network

import (
	"fmt"

	"github.com/docker/libcontainer/netlink"
	"github.com/docker/libcontainer/utils"
)

// Ipvlan is a network strategy that creates an IPVLAN device. The
// is placed inside the container's network namespace and configured
// as per the spec.
type Ipvlan struct {
}

const ipvlanPrefix = "ipvlan"
const defaultDeviceName = "eth0"

func (v *Ipvlan) Create(n *Network, nspid int, networkState *NetworkState) error {
	var (
		masterDev  = n.IpvlanMasterDeviceName
		ipvlanMode = n.IpvlanDeviceMode
	)
	if len(masterDev) == 0 {
		return fmt.Errorf("IPVLAN master device name cannot be empty.")
	}
	if len(ipvlanMode) == 0 {
		return fmt.Errorf("IPVLAN mode cannot be empty.")
	}
	ipvlanHost, err := createIpvlanDevice(masterDev, ipvlanPrefix, ipvlanMode)
	networkState.IpvlanDeviceName = ipvlanHost
	if err != nil {
		return err
	}
	if err := SetMtu(ipvlanHost, n.Mtu); err != nil {
		return err
	}
	if err := SetInterfaceInNamespacePid(ipvlanHost, nspid); err != nil {
		return err
	}
	return nil
}

func (v *Ipvlan) Initialize(config *Network, networkState *NetworkState) error {
	ipvlanOld := networkState.IpvlanDeviceName
	ipvlanNew := config.IpvlanDeviceName
	if len(ipvlanOld) == 0 {
		return fmt.Errorf("empty ipvlan device name: %s", ipvlanOld)
	}
	if err := InterfaceDown(ipvlanOld); err != nil {
		return fmt.Errorf("interface down %s: %s", ipvlanOld, err)
	}
	if len(ipvlanNew) == 0 {
		ipvlanNew = defaultDeviceName
	}
	if err := ChangeInterfaceName(ipvlanOld, ipvlanNew); err != nil {
		return fmt.Errorf(
			"change %s to %s: %s", ipvlanOld, ipvlanNew, err)
	}
	networkState.IpvlanDeviceName = ipvlanNew
	if config.MacAddress != "" {
		if err := SetInterfaceMac(ipvlanNew, config.MacAddress); err != nil {
			return fmt.Errorf("set %s mac %s: %s",
				ipvlanNew, config.MacAddress, err)
		}
	}
	if err := SetInterfaceIp(ipvlanNew, config.Address); err != nil {
		return fmt.Errorf("set %s ip %s: %s", ipvlanNew, config.Address, err)
	}
	if config.IPv6Address != "" {
		if err := SetInterfaceIp(ipvlanNew, config.IPv6Address); err != nil {
			return fmt.Errorf("set %s ipv6 %s: %s",
				ipvlanNew, config.IPv6Address, err)
		}
	}

	if err := SetMtu(ipvlanNew, config.Mtu); err != nil {
		return fmt.Errorf("set %s mtu to %d %s",
			ipvlanNew, config.Mtu, err)
	}
	if err := SetTxQueueLength(ipvlanNew, config.TxQueueLen); err != nil {
		return fmt.Errorf("set %s tx queue len to %d: %s",
			ipvlanNew, config.TxQueueLen, err)
	}
	if err := InterfaceUp(ipvlanNew); err != nil {
		return fmt.Errorf("%s up: %s", ipvlanNew, err)
	}
	if config.Gateway != "" {
		if err := SetDefaultGateway(config.Gateway, ipvlanNew); err != nil {
			return fmt.Errorf("set gateway to %s on device %s: %s",
				config.Gateway, ipvlanNew, err)
		}
	}
	if config.IPv6Gateway != "" {
		if err := SetDefaultGateway(config.IPv6Gateway, ipvlanNew); err != nil {
			return fmt.Errorf("set gateway for ipv6 to %s on device %s: %s",
				config.IPv6Gateway, ipvlanNew, err)
		}
	}

	return nil
}

// Generate a random name for IPVLAN device and ensure it gets created.
func createIpvlanDevice(masterDev, prefix, mode string) (ifname string, err error) {
	for i := 0; i < 10; i++ {
		if ifname, err = utils.GenerateRandomName(prefix, 7); err != nil {
			return
		}

		if err = CreateIpvlanDevice(masterDev, ifname, mode); err != nil {
			if err == netlink.ErrInterfaceExists {
				continue
			}
			return
		}
		break
	}
	return
}
