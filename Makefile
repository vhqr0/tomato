all: bin/vpn bin/ping bin/proxy

bin/vpn: vpn/*.go cmd/vpn/*.go
	CGO_ENABLED=0 go build -o ./bin ./cmd/vpn

bin/ping: ping/*.go cmd/ping/*.go
	CGO_ENABLED=0 go build -o ./bin ./cmd/ping

bin/proxy: proxy/*.go cmd/proxy/*.go
	CGO_ENABLED=0 go build -o ./bin ./cmd/proxy
