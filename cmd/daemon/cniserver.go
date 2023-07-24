package main

import "github.com/Ubbo-Sathla/cni-ovs/pkg/daemon"

func main() {
	c := &daemon.Configuration{
		BindSocket: "/run/openvswitch/bonc-daemon.sock",
	}
	daemon.RunServer(c)
}
