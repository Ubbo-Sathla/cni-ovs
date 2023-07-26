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

	macAddr := podRequest.IpamResult.Interfaces[0].Mac
	klog.Info("mac: ", macAddr)

	ipAddr := podRequest.IpamResult.IPs[0].Address.String()
	klog.Info("ip: ", ipAddr)

	mtu := csh.Config.MTU
	klog.Info("mtu: ", mtu)

	//err := csh.configureNic(podRequest.PodName, podRequest.PodNamespace, podRequest.Provider, podRequest.NetNs, podRequest.ContainerID, podRequest.IfName, macAddr, mtu, ipAddr, gw, isDefaultRoute, detectIPConflict, routes, nicType, gatewayCheckMode, u2oInterconnectionIP)

	// TODO: Return pod interface information
	response := &request.CniResponse{}

	if err := resp.WriteHeaderAndEntity(http.StatusOK, response); err != nil {
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
