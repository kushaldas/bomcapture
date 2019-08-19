package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-redis/redis/v7"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"encoding/json"
)

type BDNS struct {
	Name  string
	Type  string
	Class string
}

// parse each packet
func parsePacket(packet gopacket.Packet) ([]BDNS, error) {
	result := make([]BDNS, 0)
	if packet.ErrorLayer() != nil {
		// Means we have error in parsing the packet.
		// For now we will just skip the packet.
		log.Panic("Error in parsing the packet.")
		return result, errors.New("Error in parting packet")
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
				//fmt.Println(string(q.Name), q.Type, q.Class)
				result = append(result, BDNS{string(q.Name), q.Type.String(), q.Class.String()})

			}

		}
	}
	return result, nil
}

func startCapture(device string, stdout bool) {
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

	redisdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // use default Addr
		Password: "",               // no password set
		DB:       0,                // use default DB
	})

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		res, err := parsePacket(packet) // Do something with a packet here.
		if err == nil {
			if len(res) > 0 {
				//fmt.Println(res)
				if !stdout {
					res2json, _ := json.Marshal(res)
					redisdb.RPush("dnsqueue", res2json)
				} else {
					fmt.Println(res[0].Name, res[0].Type, res[0].Class)
				}
			}
		}

	}

}

/*
Entry point for the executable
*/
func main() {
	log.SetOutput(os.Stderr)
	device := flag.String("device", "wg0", "The device to capture (as root).")
	stdout := flag.Bool("stdout", false, "Print output only on stdout")
	flag.Parse()

	startCapture(*device, *stdout)
}
