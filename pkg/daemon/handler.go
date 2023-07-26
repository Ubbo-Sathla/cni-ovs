package daemon

import (
	"fmt"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/request"
	"github.com/emicklei/go-restful/v3"
	"k8s.io/klog/v2"
	"net/http"
)

const (
	gatewayModeDisabled = iota
	gatewayCheckModePing
	gatewayCheckModeArping
	gatewayCheckModePingNotConcerned
	gatewayCheckModeArpingNotConcerned
)

type cniServerHandler struct {
	Config *Configuration
}

func (csh cniServerHandler) handleAdd(req *restful.Request, resp *restful.Response) {
	podRequest := request.CniRequest{}
	if err := req.ReadEntity(&podRequest); err != nil {
		errMsg := fmt.Errorf("parse add request failed %v", err)
		klog.Error(errMsg)
		if err := resp.WriteHeaderAndEntity(http.StatusBadRequest, request.CniResponse{Err: errMsg.Error()}); err != nil {
			klog.Errorf("failed to write response, %v", err)
		}
		return
	}
	klog.Infof("request body is %#v", podRequest)

	// TODO: Add interface to ovs
	var err error

	//var macAddr, ip, ipAddr, cidr, gw, subnet, ingress, egress, providerNetwork, ifName, nicType, podNicName, vmName, latency, limit, loss, jitter, u2oInterconnectionIP string
	//var mtu int
	//
	//mtu = csh.Config.MTU
	//
	//err = csh.configureNic(podRequest.PodName, podRequest.PodNamespace, podRequest.Provider, podRequest.NetNs, podRequest.ContainerID, podRequest.VfDriver, ifName, macAddr, mtu, ipAddr, gw, isDefaultRoute, detectIPConflict, routes, podRequest.DNS.Nameservers, podRequest.DNS.Search, ingress, egress, podRequest.DeviceID, nicType, latency, limit, loss, jitter, gatewayCheckMode, u2oInterconnectionIP)

	// TODO: Return pod interface information
	response := &request.CniResponse{}

	if err = resp.WriteHeaderAndEntity(http.StatusOK, response); err != nil {
		klog.Errorf("failed to write response, %v", err)
	}
}

func (csh cniServerHandler) handleDel(req *restful.Request, resp *restful.Response) {
	var podRequest request.CniRequest
	if err := req.ReadEntity(&podRequest); err != nil {
		errMsg := fmt.Errorf("parse del request failed %v", err)
		klog.Error(errMsg)
		if err := resp.WriteHeaderAndEntity(http.StatusBadRequest, request.CniResponse{Err: errMsg.Error()}); err != nil {
			klog.Errorf("failed to write response, %v", err)
		}
		return
	}

	resp.WriteHeader(http.StatusNoContent)
}
