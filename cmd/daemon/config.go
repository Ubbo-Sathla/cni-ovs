package main

import (
	"k8s.io/client-go/kubernetes"
)

// Configuration is the daemon conf
type Configuration struct {
	// interface being used for tunnel
	tunnelIface               string
	Iface                     string
	DPDKTunnelIface           string
	MTU                       int
	MSS                       int
	EnableMirror              bool
	MirrorNic                 string
	BindSocket                string
	OvsSocket                 string
	KubeConfigFile            string
	KubeClient                kubernetes.Interface
	NodeName                  string
	ServiceClusterIPRange     string
	ClusterRouter             string
	NodeSwitch                string
	EncapChecksum             bool
	EnablePprof               bool
	MacLearningFallback       bool
	PprofPort                 int
	NetworkType               string
	CniConfDir                string
	CniConfFile               string
	CniConfName               string
	DefaultProviderName       string
	DefaultInterfaceName      string
	ExternalGatewayConfigNS   string
	ExternalGatewaySwitch     string // provider network underlay vlan subnet
	EnableMetrics             bool
	EnableArpDetectIPConflict bool
	KubeletDir                string
	EnableVerboseConnCheck    bool
	TCPConnCheckPort          int
	UDPConnCheckPort          int
	EnableTProxy              bool
}
