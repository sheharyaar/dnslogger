#!/bin/bash

set -ex

WHITELIST_URI=<Whitelist url>

go build -o bin/dnslog -ldflags "-s -X 'dnslog/handler.whitelistURI=${WHITELIST_URI}'" main.go
