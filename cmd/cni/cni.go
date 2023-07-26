// Copyright 2015 CNI authors
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

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/apis"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/request"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/util"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cni100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
	"net"
	"runtime"
	"strings"
)

type NetConf struct {
	types.NetConf
	ServerSocket string `json:"server_socket"`
	Provider     string `json:"provider"`
	Mode         string `json:"mode"`
	MTU          int    `json:"mtu"`
	Mac          string `json:"mac,omitempty"`

	RuntimeConfig struct {
		Mac string `json:"mac,omitempty"`
	} `json:"runtimeConfig,omitempty"`
}

// MacEnvArgs represents CNI_ARG
type MacEnvArgs struct {
	types.CommonArgs
	MAC types.UnmarshallableString `json:"mac,omitempty"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	klog.InitFlags(nil)
	flag.Set("logtostderr", "false")
	flag.Set("log_file", "/var/log/cni.log")
	flag.Parse()
	runtime.LockOSThread()

}
func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("macvlan"))
	klog.Flush()
}

func loadConf(bytes []byte, envArgs string) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}

	if envArgs != "" {
		e := MacEnvArgs{}
		err := types.LoadArgs(envArgs, &e)
		if err != nil {
			return nil, "", err
		}

		if e.MAC != "" {
			n.Mac = string(e.MAC)
		}
	}

	if n.RuntimeConfig.Mac != "" {
		n.Mac = n.RuntimeConfig.Mac
	}

	return n, n.CNIVersion, nil
}

func modeFromString(s string) (netlink.MacvlanMode, error) {
	switch s {
	case "", "bridge":
		return netlink.MACVLAN_MODE_BRIDGE, nil
	case "private":
		return netlink.MACVLAN_MODE_PRIVATE, nil
	case "vepa":
		return netlink.MACVLAN_MODE_VEPA, nil
	case "passthru":
		return netlink.MACVLAN_MODE_PASSTHRU, nil
	default:
		return 0, fmt.Errorf("unknown macvlan mode: %q", s)
	}
}

func modeToString(mode netlink.MacvlanMode) (string, error) {
	switch mode {
	case netlink.MACVLAN_MODE_BRIDGE:
		return "bridge", nil
	case netlink.MACVLAN_MODE_PRIVATE:
		return "private", nil
	case netlink.MACVLAN_MODE_VEPA:
		return "vepa", nil
	case netlink.MACVLAN_MODE_PASSTHRU:
		return "passthru", nil
	default:
		return "", fmt.Errorf("unknown macvlan mode: %q", mode)
	}
}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	klog.Info("cmdAdd", n, cniVersion)
	podName, err := parseValueFromArgs("K8S_POD_NAME", args.Args)
	if err != nil {
		return err
	}
	podNamespace, err := parseValueFromArgs("K8S_POD_NAMESPACE", args.Args)
	if err != nil {
		return err
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}
	// Invoke ipam del if err to avoid ip leak
	defer func() {
		if err != nil {
			ipam.ExecDel(n.IPAM.Type, args.StdinData)
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	ipamResult, err := cni100.NewResultFromResult(r)
	if err != nil {
		return err
	}
	klog.Infof("cmdAdd: ipam result %v", ipamResult)

	if len(ipamResult.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}

	client := request.NewCniServerClient(n.ServerSocket)
	response, err := client.Add(request.CniRequest{
		CniType:                   n.Type,
		IpamResult:                *ipamResult,
		PodName:                   podName,
		PodNamespace:              podNamespace,
		ContainerID:               args.ContainerID,
		NetNs:                     args.Netns,
		IfName:                    args.IfName,
		Provider:                  util.OvnProvider,
		Routes:                    nil,
		DNS:                       n.DNS,
		VhostUserSocketVolumeName: "",
		VhostUserSocketName:       "",
	})
	if err != nil {
		return types.NewError(types.ErrTryAgainLater, "RPC failed", err.Error())
	}

	result := generateCNIResult(response, args.Netns)

	return types.PrintResult(&result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	isLayer3 := n.IPAM.Type != ""

	if isLayer3 {
		err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		if err := ip.DelLinkByName(args.IfName); err != nil {
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})

	if err != nil {
		//  if NetNs is passed down by the Cloud Orchestration Engine, or if it called multiple times
		// so don't return an error if the device is already removed.
		// https://github.com/kubernetes/kubernetes/issues/43014#issuecomment-287164444
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			return nil
		}
		return err
	}

	return err
}

func cmdCheck(args *skel.CmdArgs) error {

	n, _, err := loadConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	isLayer3 := n.IPAM.Type != ""

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	if isLayer3 {
		// run the IPAM plugin and get back the config to apply
		err = ipam.ExecCheck(n.IPAM.Type, args.StdinData)
		if err != nil {
			return err
		}
	}

	// Parse previous result.
	if n.NetConf.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&n.NetConf); err != nil {
		return err
	}

	result, err := cni100.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}
	klog.Info("cmdCheck: ", result)

	var contMap cni100.Interface
	// Find interfaces for names whe know, macvlan device name inside container
	for _, intf := range result.Interfaces {
		if args.IfName == intf.Name {
			if args.Netns == intf.Sandbox {
				contMap = *intf
				continue
			}
		}
	}

	// The namespace must be the same as what was configured
	if args.Netns != contMap.Sandbox {
		return fmt.Errorf("Sandbox in prevResult %s doesn't match configured netns: %s",
			contMap.Sandbox, args.Netns)
	}

	// Check prevResults for ips, routes and dns against values found in the container
	if err := netns.Do(func(_ ns.NetNS) error {

		// Check interface against values found in the container

		err = ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs)
		if err != nil {
			return err
		}

		err = ip.ValidateExpectedRoute(result.Routes)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func generateCNIResult(cniResponse *request.CniResponse, netns string) cni100.Result {
	result := cni100.Result{
		CNIVersion: cni100.ImplementedSpecVersion,
		DNS:        cniResponse.DNS,
	}
	_, mask, _ := net.ParseCIDR(cniResponse.CIDR)
	podIface := cni100.Interface{
		Name:    cniResponse.PodNicName,
		Mac:     cniResponse.MacAddress,
		Sandbox: netns,
	}
	switch cniResponse.Protocol {
	case apis.ProtocolIPv4:
		ip, route := assignV4Address(cniResponse.IpAddress, cniResponse.Gateway, mask)
		result.IPs = []*cni100.IPConfig{ip}
		if route != nil {
			result.Routes = []*types.Route{route}
		}
		result.Interfaces = []*cni100.Interface{&podIface}
	case apis.ProtocolIPv6:
		ip, route := assignV6Address(cniResponse.IpAddress, cniResponse.Gateway, mask)
		result.IPs = []*cni100.IPConfig{ip}
		if route != nil {
			result.Routes = []*types.Route{route}
		}
		result.Interfaces = []*cni100.Interface{&podIface}
	case apis.ProtocolDual:
		var netMask *net.IPNet
		var gwStr string
		for _, cidrBlock := range strings.Split(cniResponse.CIDR, ",") {
			_, netMask, _ = net.ParseCIDR(cidrBlock)
			gwStr = ""
			if util.CheckProtocol(cidrBlock) == apis.ProtocolIPv4 {
				ipStr := strings.Split(cniResponse.IpAddress, ",")[0]
				if cniResponse.Gateway != "" {
					gwStr = strings.Split(cniResponse.Gateway, ",")[0]
				}

				ip, route := assignV4Address(ipStr, gwStr, netMask)
				result.IPs = append(result.IPs, ip)
				if route != nil {
					result.Routes = append(result.Routes, route)
				}
			} else if util.CheckProtocol(cidrBlock) == apis.ProtocolIPv6 {
				ipStr := strings.Split(cniResponse.IpAddress, ",")[1]
				if cniResponse.Gateway != "" {
					gwStr = strings.Split(cniResponse.Gateway, ",")[1]
				}

				ip, route := assignV6Address(ipStr, gwStr, netMask)
				result.IPs = append(result.IPs, ip)
				if route != nil {
					result.Routes = append(result.Routes, route)
				}
			}
		}
		result.Interfaces = []*cni100.Interface{&podIface}
	}

	return result
}
func parseValueFromArgs(key, argString string) (string, error) {
	if argString == "" {
		return "", types.NewError(types.ErrInvalidNetworkConfig, "Invalid Configuration", "CNI_ARGS is required")
	}
	args := strings.Split(argString, ";")
	for _, arg := range args {
		if strings.HasPrefix(arg, fmt.Sprintf("%s=", key)) {
			value := strings.TrimPrefix(arg, fmt.Sprintf("%s=", key))
			if len(value) > 0 {
				return value, nil
			}
		}
	}
	return "", types.NewError(types.ErrInvalidNetworkConfig, "Invalid Configuration", fmt.Sprintf("%s is required in CNI_ARGS", key))
}

func assignV4Address(ipAddress, gateway string, mask *net.IPNet) (*cni100.IPConfig, *types.Route) {
	ip := &cni100.IPConfig{
		Address:   net.IPNet{IP: net.ParseIP(ipAddress).To4(), Mask: mask.Mask},
		Gateway:   net.ParseIP(gateway).To4(),
		Interface: cni100.Int(0),
	}

	var route *types.Route
	if gw := net.ParseIP(gateway); gw != nil {
		route = &types.Route{
			Dst: net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			GW:  net.ParseIP(gateway).To4(),
		}
	}

	return ip, route
}

func assignV6Address(ipAddress, gateway string, mask *net.IPNet) (*cni100.IPConfig, *types.Route) {
	ip := &cni100.IPConfig{
		Address:   net.IPNet{IP: net.ParseIP(ipAddress).To16(), Mask: mask.Mask},
		Gateway:   net.ParseIP(gateway).To16(),
		Interface: cni100.Int(0),
	}

	var route *types.Route
	if gw := net.ParseIP(gateway); gw != nil {
		route = &types.Route{
			Dst: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			GW:  net.ParseIP(gateway).To16(),
		}
	}

	return ip, route
}
