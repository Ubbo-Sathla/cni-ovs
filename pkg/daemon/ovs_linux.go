package daemon

import (
	"fmt"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/apis"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/ovs"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/request"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/util"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"net"
	"os/exec"
	"strings"
	"time"
)

func (csh cniServerHandler) configureNic(podName, podNamespace, provider, netns, containerID, ifName, mac string, mtu int, ip, gateway string, isDefaultRoute, detectIPConflict bool, routes []request.Route, nicType string, gwCheckMode int, u2oInterconnectionIP string) error {
	var err error
	var hostNicName, containerNicName string
	hostNicName, containerNicName, err = setupVethPair(containerID, ifName, mtu)
	if err != nil {
		klog.Errorf("failed to create veth pair %v", err)
		return err
	}
	ipStr := util.GetIpWithoutMask(ip)
	ifaceID := ovs.PodNameToPortName(podName, podNamespace, provider)
	ovs.CleanDuplicatePort(ifaceID, hostNicName)
	// Add veth pair host end to ovs port
	output, err := ovs.Exec(ovs.MayExist, "add-port", "br-nat", hostNicName, "--",
		"set", "interface", hostNicName, fmt.Sprintf("external_ids:iface-id=%s", ifaceID),
		fmt.Sprintf("external_ids:vendor=%s", util.CniTypeName),
		fmt.Sprintf("external_ids:pod_name=%s", podName),
		fmt.Sprintf("external_ids:pod_namespace=%s", podNamespace),
		fmt.Sprintf("external_ids:ip=%s", ipStr),
		fmt.Sprintf("external_ids:pod_netns=%s", netns))
	if err != nil {
		return fmt.Errorf("add nic to ovs failed %v: %q", err, output)
	}

	// lsp and container nic must use same mac address, otherwise ovn will reject these packets by default
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("failed to parse mac %s %v", macAddr, err)
	}
	if err = configureHostNic(hostNicName); err != nil {
		return err
	}

	if containerNicName == "" {
		return nil
	}
	isUserspaceDP, err := ovs.IsUserspaceDataPath()
	if err != nil {
		return err
	}
	if isUserspaceDP {
		// turn off tx checksum
		if err = turnOffNicTxChecksum(containerNicName); err != nil {
			return err
		}
	}

	podNS, err := ns.GetNS(netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	if err = configureContainerNic(containerNicName, ifName, ip, gateway, isDefaultRoute, detectIPConflict, routes, macAddr, podNS, mtu, nicType, gwCheckMode, u2oInterconnectionIP); err != nil {
		return err
	}
	return nil
}
func configureContainerNic(nicName, ifName string, ipAddr, gateway string, isDefaultRoute, detectIPConflict bool, routes []request.Route, macAddr net.HardwareAddr, netns ns.NetNS, mtu int, nicType string, gwCheckMode int, u2oInterconnectionIP string) error {
	containerLink, err := netlink.LinkByName(nicName)
	if err != nil {
		return fmt.Errorf("can not find container nic %s: %v", nicName, err)
	}

	// Set link alias to its origin link name for fastpath to recognize and bypass netfilter
	if err := netlink.LinkSetAlias(containerLink, nicName); err != nil {
		klog.Errorf("failed to set link alias for container nic %s: %v", nicName, err)
		return err
	}

	if err = netlink.LinkSetNsFd(containerLink, int(netns.Fd())); err != nil {
		return fmt.Errorf("failed to move link to netns: %v", err)
	}

	return ns.WithNetNSPath(netns.Path(), func(_ ns.NetNS) error {
		if nicType != util.InternalType {
			if err = netlink.LinkSetName(containerLink, ifName); err != nil {
				return err
			}
		}

		if util.CheckProtocol(ipAddr) == apis.ProtocolDual || util.CheckProtocol(ipAddr) == apis.ProtocolIPv6 {
			// For docker version >=17.x the "none" network will disable ipv6 by default.
			// We have to enable ipv6 here to add v6 address and gateway.
			// See https://github.com/containernetworking/cni/issues/531
			value, err := sysctl.Sysctl("net.ipv6.conf.all.disable_ipv6")
			if err != nil {
				return fmt.Errorf("failed to get sysctl net.ipv6.conf.all.disable_ipv6: %v", err)
			}
			if value != "0" {
				if _, err = sysctl.Sysctl("net.ipv6.conf.all.disable_ipv6", "0"); err != nil {
					return fmt.Errorf("failed to enable ipv6 on all nic: %v", err)
				}
			}
		}

		if nicType == util.InternalType {
			if err = addAdditionalNic(ifName); err != nil {
				return err
			}
			if err = configureAdditionalNic(ifName, ipAddr); err != nil {
				return err
			}
			if err = configureNic(nicName, ipAddr, macAddr, mtu, detectIPConflict); err != nil {
				return err
			}
		} else {
			if err = configureNic(ifName, ipAddr, macAddr, mtu, detectIPConflict); err != nil {
				return err
			}
		}

		if isDefaultRoute {
			// Only eth0 requires the default route and gateway
			containerGw := gateway
			if u2oInterconnectionIP != "" {
				containerGw = u2oInterconnectionIP
			}

			for _, gw := range strings.Split(containerGw, ",") {
				if err = netlink.RouteReplace(&netlink.Route{
					LinkIndex: containerLink.Attrs().Index,
					Scope:     netlink.SCOPE_UNIVERSE,
					Gw:        net.ParseIP(gw),
				}); err != nil {
					return fmt.Errorf("failed to configure default gateway %s: %v", gw, err)
				}
			}
		}

		for _, r := range routes {
			var dst *net.IPNet
			if r.Destination != "" {
				if _, dst, err = net.ParseCIDR(r.Destination); err != nil {
					klog.Errorf("invalid route destination %s: %v", r.Destination, err)
					continue
				}
			}

			var gw net.IP
			if r.Gateway != "" {
				if gw = net.ParseIP(r.Gateway); gw == nil {
					klog.Errorf("invalid route gateway %s", r.Gateway)
					continue
				}
			}

			route := &netlink.Route{
				Dst:       dst,
				Gw:        gw,
				LinkIndex: containerLink.Attrs().Index,
			}
			if err = netlink.RouteReplace(route); err != nil {
				klog.Errorf("failed to add route %+v: %v", r, err)
			}
		}

		if gwCheckMode != gatewayModeDisabled {
			var (
				underlayGateway = gwCheckMode == gatewayCheckModeArping || gwCheckMode == gatewayCheckModeArpingNotConcerned
				interfaceName   = nicName
			)

			if nicType != util.InternalType {
				interfaceName = ifName
			}

			if u2oInterconnectionIP != "" {
				if err := checkGatewayReady(gwCheckMode, interfaceName, ipAddr, u2oInterconnectionIP, false, true); err != nil {
					return err
				}
			}
			return checkGatewayReady(gwCheckMode, interfaceName, ipAddr, gateway, underlayGateway, true)
		}

		return nil
	})
}

func checkGatewayReady(gwCheckMode int, intr, ipAddr, gateway string, underlayGateway, verbose bool) error {
	var err error

	if gwCheckMode == gatewayCheckModeArpingNotConcerned || gwCheckMode == gatewayCheckModePingNotConcerned {
		// ignore error if disableGatewayCheck=true
		if err = waitNetworkReady(intr, ipAddr, gateway, underlayGateway, verbose, 1); err != nil {
			err = nil
		}
	} else {
		err = waitNetworkReady(intr, ipAddr, gateway, underlayGateway, verbose, gatewayCheckMaxRetry)
	}
	return err
}
func waitNetworkReady(nic, ipAddr, gateway string, underlayGateway, verbose bool, maxRetry int) error {
	ips := strings.Split(ipAddr, ",")
	for i, gw := range strings.Split(gateway, ",") {
		src := strings.Split(ips[i], "/")[0]
		if underlayGateway && util.CheckProtocol(gw) == apis.ProtocolIPv4 {
			mac, count, err := util.ArpResolve(nic, src, gw, time.Second, maxRetry)
			if err != nil {
				err = fmt.Errorf("network %s with gateway %s is not ready for interface %s after %d checks: %v", ips[i], gw, nic, count, err)
				klog.Warning(err)
				return err
			}
			if verbose {
				klog.Infof("MAC addresses of gateway %s is %s", gw, mac.String())
				klog.Infof("network %s with gateway %s is ready for interface %s after %d checks", ips[i], gw, nic, count)
			}
			maxRetry -= count
		} else {
			count, err := pingGateway(gw, src, verbose, maxRetry)
			if err != nil {
				return err
			}
			maxRetry -= count
		}
	}
	return nil
}

func configureNic(link, ip string, macAddr net.HardwareAddr, mtu int, detectIPConflict bool) error {
	nodeLink, err := netlink.LinkByName(link)
	if err != nil {
		return fmt.Errorf("can not find nic %s: %v", link, err)
	}

	if err = netlink.LinkSetHardwareAddr(nodeLink, macAddr); err != nil {
		return fmt.Errorf("can not set mac address to nic %s: %v", link, err)
	}

	if mtu > 0 {
		if nodeLink.Type() == "openvswitch" {
			_, err = ovs.Exec("set", "interface", link, fmt.Sprintf(`mtu_request=%d`, mtu))
		} else {
			err = netlink.LinkSetMTU(nodeLink, mtu)
		}
		if err != nil {
			return fmt.Errorf("failed to set nic %s mtu: %v", link, err)
		}
	}

	if nodeLink.Attrs().OperState != netlink.OperUp {
		if err = netlink.LinkSetUp(nodeLink); err != nil {
			return fmt.Errorf("can not set node nic %s up: %v", link, err)
		}
	}

	ipDelMap := make(map[string]netlink.Addr)
	ipAddMap := make(map[string]netlink.Addr)
	ipAddrs, err := netlink.AddrList(nodeLink, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("can not get addr %s: %v", nodeLink, err)
	}
	for _, ipAddr := range ipAddrs {
		if ipAddr.IP.IsLinkLocalUnicast() {
			// skip 169.254.0.0/16 and fe80::/10
			continue
		}
		ipDelMap[ipAddr.IPNet.String()] = ipAddr
	}

	for _, ipStr := range strings.Split(ip, ",") {
		// Do not reassign same address for link
		if _, ok := ipDelMap[ipStr]; ok {
			delete(ipDelMap, ipStr)
			continue
		}

		ipAddr, err := netlink.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("can not parse address %s: %v", ipStr, err)
		}
		ipAddMap[ipStr] = *ipAddr
	}

	for ip, addr := range ipDelMap {
		klog.Infof("delete ip address %s on %s", ip, link)
		if err = netlink.AddrDel(nodeLink, &addr); err != nil {
			return fmt.Errorf("delete address %s: %v", addr, err)
		}
	}
	for ip, addr := range ipAddMap {
		if detectIPConflict && addr.IP.To4() != nil {
			ip := addr.IP.String()
			mac, err := util.ArpDetectIPConflict(link, ip, macAddr)
			if err != nil {
				err = fmt.Errorf("failed to detect address conflict for %s on link %s: %v", ip, link, err)
				klog.Error(err)
				return err
			}
			if mac != nil {
				return fmt.Errorf("IP address %s has already been used by host with MAC %s", ip, mac)
			}
		}
		if addr.IP.To4() != nil && !detectIPConflict {
			// when detectIPConflict is true, free arp is already broadcast in the step of announcement
			if err := util.AnnounceArpAddress(link, addr.IP.String(), macAddr, 1, 1*time.Second); err != nil {
				klog.Warningf("failed to broadcast free arp with err %v ", err)
			}
		}

		klog.Infof("add ip address %s to %s", ip, link)
		if err = netlink.AddrAdd(nodeLink, &addr); err != nil {
			return fmt.Errorf("can not add address %v to nic %s: %v", addr, link, err)
		}
	}

	return nil
}

func addAdditionalNic(ifName string) error {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName,
		},
	}

	if err := netlink.LinkAdd(dummy); err != nil {
		if err := netlink.LinkDel(dummy); err != nil {
			klog.Errorf("failed to delete static iface %v, err %v", ifName, err)
			return err
		}
		return fmt.Errorf("failed to create static iface %v, err %v", ifName, err)
	}
	return nil
}

func configureAdditionalNic(link, ip string) error {
	nodeLink, err := netlink.LinkByName(link)
	if err != nil {
		return fmt.Errorf("can not find nic %s %v", link, err)
	}

	ipDelMap := make(map[string]netlink.Addr)
	ipAddMap := make(map[string]netlink.Addr)
	ipAddrs, err := netlink.AddrList(nodeLink, 0x0)
	if err != nil {
		return fmt.Errorf("can not get addr %s %v", nodeLink, err)
	}
	for _, ipAddr := range ipAddrs {
		if ipAddr.IP.IsLinkLocalUnicast() {
			// skip 169.254.0.0/16 and fe80::/10
			continue
		}
		ipDelMap[ipAddr.IPNet.String()] = ipAddr
	}

	for _, ipStr := range strings.Split(ip, ",") {
		// Do not reassign same address for link
		if _, ok := ipDelMap[ipStr]; ok {
			delete(ipDelMap, ipStr)
			continue
		}

		ipAddr, err := netlink.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("can not parse %s %v", ipStr, err)
		}
		ipAddMap[ipStr] = *ipAddr
	}

	for _, addr := range ipDelMap {
		if err = netlink.AddrDel(nodeLink, &addr); err != nil {
			return fmt.Errorf("delete address %s %v", addr, err)
		}
	}
	for _, addr := range ipAddMap {
		if err = netlink.AddrAdd(nodeLink, &addr); err != nil {
			return fmt.Errorf("can not add address %v to nic %s, %v", addr, link, err)
		}
	}

	return nil
}

func setupVethPair(containerID, ifName string, mtu int) (string, string, error) {
	var err error
	hostNicName, containerNicName := generateNicName(containerID, ifName)
	// Create a veth pair, put one end to container ,the other to ovs port
	// NOTE: DO NOT use ovs internal type interface for container.
	// Kubernetes will detect 'eth0' nic in pod, so the nic name in pod must be 'eth0'.
	// When renaming internal interface to 'eth0', ovs will delete and recreate this interface.
	veth := netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostNicName}, PeerName: containerNicName}
	if mtu > 0 {
		veth.MTU = mtu
	}
	if err = netlink.LinkAdd(&veth); err != nil {
		if err := netlink.LinkDel(&veth); err != nil {
			klog.Errorf("failed to delete veth %v", err)
			return "", "", err
		}
		return "", "", fmt.Errorf("failed to create veth for %v", err)
	}
	return hostNicName, containerNicName, nil
}
func generateNicName(containerID, ifname string) (string, string) {
	if ifname == "eth0" {
		return fmt.Sprintf("%s_h", containerID[0:12]), fmt.Sprintf("%s_c", containerID[0:12])
	}
	// The nic name is 14 length and have prefix pod in the Kubevirt v1.0.0
	if strings.HasPrefix(ifname, "pod") && len(ifname) == 14 {
		ifname = ifname[3 : len(ifname)-4]
		return fmt.Sprintf("%s_%s_h", containerID[0:12-len(ifname)], ifname), fmt.Sprintf("%s_%s_c", containerID[0:12-len(ifname)], ifname)
	}
	return fmt.Sprintf("%s_%s_h", containerID[0:12-len(ifname)], ifname), fmt.Sprintf("%s_%s_c", containerID[0:12-len(ifname)], ifname)
}
func configureHostNic(nicName string) error {
	hostLink, err := netlink.LinkByName(nicName)
	if err != nil {
		return fmt.Errorf("can not find host nic %s: %v", nicName, err)
	}

	if hostLink.Attrs().OperState != netlink.OperUp {
		if err = netlink.LinkSetUp(hostLink); err != nil {
			return fmt.Errorf("can not set host nic %s up: %v", nicName, err)
		}
	}
	if err = netlink.LinkSetTxQLen(hostLink, 1000); err != nil {
		return fmt.Errorf("can not set host nic %s qlen: %v", nicName, err)
	}

	return nil
}
func turnOffNicTxChecksum(nicName string) (err error) {
	start := time.Now()
	args := []string{"-K", nicName, "tx", "off"}
	output, err := exec.Command("ethtool", args...).CombinedOutput()
	elapsed := float64((time.Since(start)) / time.Millisecond)
	klog.V(4).Infof("command %s %s in %vms", "ethtool", strings.Join(args, " "), elapsed)
	if err != nil {
		return fmt.Errorf("failed to turn off nic tx checksum, output %s, err %s", string(output), err.Error())
	}
	return nil
}
