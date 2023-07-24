
build-go:
	go mod tidy
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build  $(CURDIR)/dist/images/macvlan -v ./cmd/cni
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build  $(CURDIR)/dist/images/kube-ovs -v ./cmd/daemon
