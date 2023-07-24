
build-go:
	go mod tidy
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(CURDIR)/dist/images/cni-ovs -v ./cmd/cni
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(CURDIR)/dist/images/kube-ovs -v ./cmd/daemon
