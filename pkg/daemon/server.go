package daemon

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/klog/v2"

	"github.com/Ubbo-Sathla/cni-ovs/pkg/request"
	"github.com/Ubbo-Sathla/cni-ovs/pkg/util"
)

const (
	requestLogFormat  = "[%s] Incoming %s %s %s request"
	responseLogFormat = "[%s] Outgoing response %s %s with %d status code in %vms"
)

// RunServer runs the cniserver
func RunServer(config *Configuration) {
	csh := &cniServerHandler{Config: config}
	server := http.Server{
		Handler:           createHandler(csh),
		ReadHeaderTimeout: 3 * time.Second,
	}
	os.Remove(config.BindSocket)
	listener, cleanFunc, err := listen(config.BindSocket)
	if err != nil {
		util.LogFatalAndExit(err, "failed to listen on %s", config.BindSocket)
	}
	defer cleanFunc()
	klog.Infof("start listen on %s", config.BindSocket)
	util.LogFatalAndExit(server.Serve(listener), "failed to serve on %s", config.BindSocket)
}

func createHandler(csh *cniServerHandler) http.Handler {
	wsContainer := restful.NewContainer()
	wsContainer.EnableContentEncoding(true)

	ws := new(restful.WebService)
	ws.Path("/api/v1").
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)
	wsContainer.Add(ws)

	ws.Route(
		ws.POST("/add").
			To(csh.handleAdd).
			Reads(request.CniRequest{}))
	ws.Route(
		ws.POST("/del").
			To(csh.handleDel).
			Reads(request.CniRequest{}))

	ws.Filter(requestAndResponseLogger)

	return wsContainer
}

// web-service filter function used for request and response logging.
func requestAndResponseLogger(request *restful.Request, response *restful.Response,
	chain *restful.FilterChain) {
	klog.Infof(formatRequestLog(request))
	start := time.Now()
	chain.ProcessFilter(request, response)
	elapsed := float64((time.Since(start)) / time.Millisecond)
	klog.Infof(formatResponseLog(response, request, elapsed))
}

// formatRequestLog formats request log string.
func formatRequestLog(request *restful.Request) string {
	return fmt.Sprintf(requestLogFormat, time.Now().Format(time.RFC3339), request.Request.Proto,
		request.Request.Method, getRequestURI(request))
}

// formatResponseLog formats response log string.
func formatResponseLog(response *restful.Response, request *restful.Request, reqTime float64) string {
	return fmt.Sprintf(responseLogFormat, time.Now().Format(time.RFC3339),
		request.Request.Method, getRequestURI(request), response.StatusCode(), reqTime)
}

// getRequestURI get the request uri
func getRequestURI(request *restful.Request) (uri string) {
	if request.Request.URL != nil {
		uri = request.Request.URL.RequestURI()
	}
	return
}
