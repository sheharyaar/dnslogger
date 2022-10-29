# Design

Uses a simple design with 2 buffers which are extensible (currently using go channels) and can be replaced by any suitable API. Similarly, sendData is also extensible.


# Code

```
.
|-- go.mod
|-- go.sum
|-- handler
|   |-- packetHandler.go              // contains packet handling and filtering
|   `-- sendData.go                   // contains send data
`-- main.go                           // contains packet capture using gopcap
```

### To build and run :

Obtain the following first:

- Whitelist file URL ( a regex based list on a remote location which can be fetched. Example list is provided in the file `whitelistDns` )

- The whitelist resource must change it's `Etag` if whitelist changes on the remote resource as the code checks for changes in etag for updating the whitelist.

Place these values in `build.sh` and run:

```console
$ go mod init dnslog
$ go mod tidy
$ ./build.sh

# Run as sudo
$ sudo ./bin/dnslog
```
# Performance

- Here golang package `gopcap` is being used which is a wrapper around `libpcap`. This is slower than direct implementation using `libpcap` in C.

- Here `pcap` is being used. Much better solutions like `tc-bpf` could have been used for better performance in case of large number of packet transfers. Using kernel tracepoints in the kernel would have been much faster as pcap processes raw packets which are generally used for processing packets. For logging we don't need to process the packets.
