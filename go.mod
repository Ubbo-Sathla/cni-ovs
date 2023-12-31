module github.com/Ubbo-Sathla/cni-ovs

go 1.20

require (
	github.com/containernetworking/cni v1.1.2
	github.com/containernetworking/plugins v1.3.0
	github.com/emicklei/go-restful/v3 v3.9.0
	github.com/mdlayher/arp v0.0.0-20220512170110-6706a2966875
	github.com/parnurzeal/gorequest v0.2.16
	github.com/prometheus-community/pro-bing v0.3.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	golang.org/x/sys v0.10.0
	k8s.io/klog/v2 v2.100.1

)

require (
	github.com/coreos/go-iptables v0.6.0 // indirect
	github.com/elazarl/goproxy v0.0.0-20221015165544-a0805db90819 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/google/pprof v0.0.0-20230510103437-eeec1cb781c3 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mdlayher/ethernet v0.0.0-20220221185849-529eae5b6118 // indirect
	github.com/mdlayher/packet v1.1.1 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/onsi/ginkgo/v2 v2.11.0 // indirect
	github.com/onsi/gomega v1.27.8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/smartystreets/goconvey v1.8.1 // indirect
	github.com/stretchr/testify v1.8.1 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/net v0.11.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	moul.io/http2curl v1.0.0 // indirect
)

replace (
	github.com/alauda/felix => github.com/kubeovn/felix v0.0.0-20220325073257-c8a0f705d139
	github.com/greenpau/ovsdb => github.com/kubeovn/ovsdb v0.0.0-20221213053943-9372db56919f
	github.com/mdlayher/arp => github.com/kubeovn/arp v0.0.0-20230101053045-8a0772d9c34c
	github.com/openshift/client-go => github.com/openshift/client-go v0.0.0-20221107163225-3335a34a1d24
	github.com/ovn-org/libovsdb => github.com/kubeovn/libovsdb v0.0.0-20230517064328-9d5a1383643f
	github.com/vishvananda/netlink => github.com/kubeovn/netlink v0.0.0-20230322092337-960188369daf
	k8s.io/api => k8s.io/api v0.27.3
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.27.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.27.3
	k8s.io/apiserver => k8s.io/apiserver v0.27.3
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.27.3
	k8s.io/client-go => k8s.io/client-go v0.27.3
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.27.3
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.27.3
	k8s.io/code-generator => k8s.io/code-generator v0.27.3
	k8s.io/component-base => k8s.io/component-base v0.27.3
	k8s.io/component-helpers => k8s.io/component-helpers v0.27.3
	k8s.io/controller-manager => k8s.io/controller-manager v0.27.3
	k8s.io/cri-api => k8s.io/cri-api v0.27.3
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.27.3
	k8s.io/dynamic-resource-allocation => k8s.io/dynamic-resource-allocation v0.27.3
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.27.3
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.27.3
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.27.3
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.27.3
	k8s.io/kubectl => k8s.io/kubectl v0.27.3
	k8s.io/kubelet => k8s.io/kubelet v0.27.3
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.27.3
	k8s.io/metrics => k8s.io/metrics v0.27.3
	k8s.io/mount-utils => k8s.io/mount-utils v0.27.3
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.27.3
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.27.3
	kubevirt.io/client-go => github.com/kubeovn/kubevirt-client-go v0.0.0-20230517062539-8dd832f39ec5
)
