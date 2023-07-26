package util

import (
	"github.com/Ubbo-Sathla/cni-ovs/pkg/apis"
	"net"
	"strings"
)

func GetIpWithoutMask(ipStr string) string {
	var ips []string
	for _, ip := range strings.Split(ipStr, ",") {
		ips = append(ips, strings.Split(ip, "/")[0])
	}
	return strings.Join(ips, ",")
}

func CheckProtocol(address string) string {
	ips := strings.Split(address, ",")
	if len(ips) == 2 {
		IP1 := net.ParseIP(strings.Split(ips[0], "/")[0])
		IP2 := net.ParseIP(strings.Split(ips[1], "/")[0])
		if IP1.To4() != nil && IP2.To4() == nil && IP2.To16() != nil {
			return apis.ProtocolDual
		}
		if IP2.To4() != nil && IP1.To4() == nil && IP1.To16() != nil {
			return apis.ProtocolDual
		}
		return ""
	}

	address = strings.Split(address, "/")[0]
	ip := net.ParseIP(address)
	if ip.To4() != nil {
		return apis.ProtocolIPv4
	} else if ip.To16() != nil {
		return apis.ProtocolIPv6
	}

	// cidr formal error
	return ""
}
