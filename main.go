package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// parse each packet
func parsePacket(packet gopacket.Packet) {
	if packet.ErrorLayer() != nil {
		// Means we have error in parsing the packet.
		// For now we will just skip the packet.
		log.Panic("Error in parsing the packet.")
		return
	}

	//fmt.Println(packet)
	// If we are here, means we can successfuly parse the packet.
	for _, layer := range packet.Layers() {
		// fmt.Println("PACKET LAYER:", layer.LayerType())

		// if layer.LayerType() == layers.LayerTypeIPv4 {
		// 	l := layer.(*layers.IPv4)
		// 	fmt.Println(l.SrcIP, l.DstIP)

		// }
		if layer.LayerType() == layers.LayerTypeDNS {
			l := layer.(*layers.DNS)
			qs := l.Questions
			for _, q := range qs {
				fmt.Println(string(q.Name), q.Type, q.Class)
			}

		}
	}
	//fmt.Println("=========================================")
}

func startCapture(device string) {
	inactive, err := pcap.NewInactiveHandle(device)
	if err != nil {
		log.Fatal(err)
	}
	defer inactive.CleanUp()

	// Finally, create the actual handle by calling Activate:
	handle, err := inactive.Activate() // after this, inactive is no longer valid
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parsePacket(packet) // Do something with a packet here.
	}

}

/*
Entry point for the executable
*/
func main() {
	log.SetOutput(os.Stderr)
	device := flag.String("device", "wg0", "The device to capture (as root).")
	flag.Parse()

	startCapture(*device)
}
