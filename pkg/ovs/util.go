package ovs

import (
	"fmt"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/util"
	"strings"
)

// PodNameToPortName return the ovn port name for a given pod
func PodNameToPortName(pod, namespace, provider string) string {
	return fmt.Sprintf("%s.%s.%s", pod, namespace, util.OvnProvider)
}

func trimCommandOutput(raw []byte) string {
	output := strings.TrimSpace(string(raw))
	return strings.Trim(output, "\"")
}
