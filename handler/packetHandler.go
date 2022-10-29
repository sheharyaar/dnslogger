// Source code for handling DNS packets
package handler

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

var (
	WhitelistURI = ""
)

// global because there will be only one etag
var etagStruct struct {
	sync.Mutex
	etag string
}

// returns the current value of etag
func getEtag() string {
	etagStruct.Lock()
	defer etagStruct.Unlock()

	etag := etagStruct.etag

	return etag
}

// sets the etag
func setEtag(newEtag string) {
	etagStruct.Lock()
	defer etagStruct.Unlock()

	etagStruct.etag = newEtag
}

// Handles packets from pcap capture.
//
// It creates a whitelist file using the whitelist uri given during build time
func HandlePacket(packetBuffer <-chan gopacket.Packet, sendBuffer chan<- SendDataStruct) {
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	// creates the file and sets the etag
	var whitelist *os.File = updateWhiteList(nil)
	defer whitelist.Close()

	// store etag for comparison
	etag := getEtag()

	for {
		var sendData SendDataStruct

		// check for etag updates
		if getEtag() != etag {
			whitelist = updateWhiteList(whitelist)
			etag = getEtag()
		}

		packet := <-packetBuffer

		// Check if packet type is DNS and then write the DNS Question name to file
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dnsContent := dnsLayer.(*layers.DNS)
			for _, question := range dnsContent.Questions {
				if FilterPacket(&question, whitelist) != 0 {
					continue
				}
				// constructs a string of format : <timestamp> <dns name> <newline>
				// calling time.Now here instead of the caller function as the time diff will be quite low
				// otherwise we would have to append time to the packet byte which would be complex to unpack
				sendData.QueryName = string(question.Name)
				sendData.QueryType = question.Type.String()
				sendData.TimePacket = time.Now()
				sendData.Host = hostname

				sendBuffer <- sendData
			}
		}
	}
}

// Takes in dnsQuestion (pointer to prevent copying performance loss).
// Returns non zero when packet needs to be dropped.
// We can mmap a file for whitelisting for faster read access
//
// FQDN format :
// <hostname>.<subdomain 1>.<subdomain 2>.<domain>.<top level domain (TLD)>.
//
// Eg : www.app.dealtable.com
func FilterPacket(question *layers.DNSQuestion, whitelist *os.File) int {
	name := string(question.Name)

	// Trim the ending "." in FQDN (root)
	name = strings.TrimSuffix(name, ".")
	stringsName := strings.Split(name, ".")
	//	First reject TLDs with "local" for pods -> eg : api.ipify.org.ni-dev.svc.cluster.local
	// Don't remove this because it's ther to avoid dns requests that go to the cluster (which we
	// need to ingore)
	if stringsName[len(stringsName)-1] == "local" {
		return 1
	}
	// regex : golang regexp uses re2 engine hence it is linear to the length
	// of the regex string
	scanner := bufio.NewScanner(whitelist)
	if scanner == nil {
		panic("Couldn't scan whitelist")
	}

	scanner.Split(bufio.ScanLines)

	// Reset the file seek to beginning
	whitelist.Seek(0, io.SeekStart)

	for scanner.Scan() {
		pattern := scanner.Text()
		found, _ := regexp.MatchString(pattern, name)
		if found {
			return 1
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return 1
	}

	return 0
}

/*
Check for etag updates and updates the etag
*/
func UpdatesWatcher() {

	for {
		resp, err := http.Get(WhitelistURI)
		if err != nil {
			panic(err)
		}

		// get etag
		etag := resp.Header.Get("Etag")
		if etag == "" {
			panic("Etag not found in header")
		}

		// Check every 10 minutes for updates

		if etag != getEtag() {
			setEtag(etag)
		}

		resp.Body.Close()
		time.Sleep(5 * time.Minute)
	}

}

/*
Updates the whitelist file.
If argument is nil, creates a new file.
Stores open file flags -> closes the file -> creates a new file -> resets flags -> returns the new etag
*/
func updateWhiteList(whitelist *os.File) *os.File {

	var flags int = -1
	var err error

	// save flags, close file and then delete it
	if whitelist != nil {
		//	save flags
		//	last argument is random as it will be ignoreed
		//	check manpage of fcntl
		flags, err = unix.FcntlInt(whitelist.Fd(), unix.F_GETFL, 0)
		if err != nil {
			panic(err)
		}

		fileName := whitelist.Name()

		whitelist.Close()

		err = os.Remove(fileName)
		if err != nil {
			panic(err)
		}
	}

	resp, err := http.Get(WhitelistURI)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// get etag
	etag := resp.Header.Get("Etag")
	if etag == "" {
		panic("Etag not found in header")
	}

	//download whitelist and open the file to write data
	whitelist, err = os.OpenFile("whitelist-"+etag, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		panic(err)
	}

	bytes, err := io.Copy(whitelist, resp.Body)
	if err != nil {
		panic(err)
	}

	if fmt.Sprintf("%d", bytes) != resp.Header.Get("Content-Length") {
		panic("Couldn't get full DNS whitelist")
	}

	//if download was successfull reset the flags (if they are present else set to readonly)

	if flags != -1 {
		_, err = unix.FcntlInt(whitelist.Fd(), unix.F_SETFL, flags)
	} else {
		_, err = unix.FcntlInt(whitelist.Fd(), unix.F_SETFL, os.O_RDONLY)
	}

	if err != nil {
		panic(err)
	}

	// set etag and return
	setEtag(etag)

	return whitelist
}
