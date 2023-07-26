package daemon

import (
	"fmt"
	goping "github.com/prometheus-community/pro-bing"
	"k8s.io/klog/v2"

	"time"
)

const gatewayCheckMaxRetry = 200

func pingGateway(gw, src string, verbose bool, maxRetry int) (count int, err error) {
	pinger, err := goping.NewPinger(gw)
	if err != nil {
		return 0, fmt.Errorf("failed to init pinger: %v", err)
	}
	pinger.SetPrivileged(true)
	// CNITimeoutSec = 220, cannot exceed
	pinger.Count = maxRetry
	pinger.Timeout = time.Duration(maxRetry) * time.Second
	pinger.Interval = time.Second

	pinger.OnRecv = func(p *goping.Packet) {
		pinger.Stop()
	}

	pinger.OnSend = func(p *goping.Packet) {
		if pinger.PacketsRecv == 0 && pinger.PacketsSent != 0 && pinger.PacketsSent%3 == 0 {
			klog.Warningf("%s network not ready after %d ping to gateway %s", src, pinger.PacketsSent, gw)
		}
	}

	if err = pinger.Run(); err != nil {
		klog.Errorf("failed to run pinger for destination %s: %v", gw, err)
		return 0, err
	}

	if verbose {
		klog.Infof("%s network ready after %d ping, gw %s", src, pinger.PacketsSent, gw)
	}

	return pinger.PacketsSent, nil
}
