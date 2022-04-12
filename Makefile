VERSION ?= $(shell cat VERSION)

build:
	GOOS=linux GOARCH=amd64 go build -o vuls_exporter-${VERSION}-linux .
	go build -o vuls_exporter-${VERSION}-darwin .
