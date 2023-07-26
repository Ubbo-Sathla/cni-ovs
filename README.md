# cni-ovs

> 有限环境下，配置[kube-ovn](https://github.com/kubeovn/kube-ovn) vpc出网, 使用multus创建自己写cni 创建第二块网卡，接入到kube-ovn中的ovs的桥上...

## vpc

```ovn-vpc-external-network.yaml
apiVersion: kubeovn.io/v1
kind: Subnet
metadata:
  name: ovn-vpc-external-network
spec:
  protocol: IPv4
  provider: ovn-vpc-external-network.kube-system
  cidrBlock: 10.17.0.0/24
  gateway: 10.17.0.1
  excludeIps:
  - 10.17.0.1
```


```multus
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: ovn-vpc-external-network
  namespace: kube-system

spec:
  config: |
    {
      "cniVersion": "0.3.0",
      "server_socket": "/run/openvswitch/bonc-daemon.sock",
      "type": "cni-ovs",
      "master": "br-nat",
      "mode": "bridge",
      "ipam": {
        "type": "kube-ovn",
        "server_socket": "/run/openvswitch/kube-ovn-daemon.sock",
        "provider": "ovn-vpc-external-network.kube-system"
      }
    }
```

![ovs.jpg](images%2Fovs.jpg)

![pod.jpg](images%2Fpod.jpg)