package main

import (
	"dnslog/handler"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	// Check for root privileges for capturing packets
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Need root privileges to run the program! Try again with sudo\n")
		os.Exit(1)
	}

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Print device information
	log.Println("\n\n[INFO] Devices found:")
	for _, device := range devices {
		log.Println("\n\n[INFO] Name: ", device.Name)
		log.Println("[INFO] Description: ", device.Description)
		for _, address := range device.Addresses {
			log.Println("- IP address: ", address.IP)
		}
	}

	// Read live packets
	// eth0 -> interface
	// 1600 -> max size
	// true -> promiscuous mode
	// pcap.BlockForever -> listen forever (no timeout)
	// Check : https://pkg.go.dev/github.com/google/gopacket/pcap#OpenLive

	// device[0] -> default used device
	var PACKET_LIMIT_BUF int64 = 1024

	captureDevice := devices[0].Name
	log.Println("\n\n[INFO] Using the following device to capture packets : ", captureDevice)

	if handle, err := pcap.OpenLive(captureDevice, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and dst port 53"); err != nil { // set pcap BPF filter
		// using dst port 53 to capture egress DNS packets
		panic(err)
	} else {

		// make a channels and start the Handlers in another thread
		packetBuffer := make(chan gopacket.Packet, PACKET_LIMIT_BUF)      // channel for packets main->handler
		sendBuffer := make(chan handler.SendDataStruct, PACKET_LIMIT_BUF) // channel for packets handler->sendFunction

		go handler.HandlePacket(packetBuffer, sendBuffer) //handles packes and sends to sendbuffe
		go handler.SendData(sendBuffer)                   // reads data from sendBuffer and  sends on socket
		go handler.UpdatesWatcher()                       // checks for ETag update

		// Close the handle before exit
		defer handle.Close()
		defer close(packetBuffer)
		defer close(sendBuffer)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// push to the channel
			packetBuffer <- packet
		}
	}

}
