package capturing

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"encoding/json"

	"github.com/go-redis/redis/v7"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type OwnPackets interface {
	Json() []byte
}

type BDNS struct {
	PacketType string
	Name       string
	Type       string
	Class      string
	Ips        []string
}

func (p BDNS) Json() []byte {
	res2json, _ := json.Marshal(p)
	return res2json
}

type BPackets struct {
	PacketType string
	Src        string
	Dest       string
	Sport      int
	Dport      int
}

func (p BPackets) Json() []byte {
	res2json, _ := json.Marshal(p)
	return res2json
}

// parse each packet
func ParsePacket(packet gopacket.Packet, onlyDNS bool) ([]OwnPackets, error) {
	// Flag to mark a DNS packet for DoH
	dnsPacket := false
	result := make([]OwnPackets, 0)
	if packet.ErrorLayer() != nil {
		// Means we have error in parsing the packet.
		// For now we will just skip the packet.
		log.Panic("Error in parsing the packet.")
		return result, errors.New("Error in parting packet")
	}

	//fmt.Println(packet)
	// If we are here, means we can successfuly parse the packet.
	tcpS := BPackets{}
	tcpS.PacketType = "Packet"
	for _, layer := range packet.Layers() {
		// fmt.Println("PACKET LAYER:", layer.LayerType())

		if layer.LayerType() == layers.LayerTypeTCP {
			l := layer.(*layers.TCP)
			sport := int(l.SrcPort)
			dport := int(l.DstPort)
			tcpS.Sport = sport
			tcpS.Dport = dport
		} else if layer.LayerType() == layers.LayerTypeIPv4 {
			l := layer.(*layers.IPv4)
			tcpS.Src = l.SrcIP.String()
			tcpS.Dest = l.DstIP.String()

		} else if layer.LayerType() == layers.LayerTypeDNS {
			dnsPacket = true
			l := layer.(*layers.DNS)
			ipv4 := make([]string, 0)
			ipv6 := make([]string, 0)
			var ips []string
			qs := l.Questions

			// If it is a response, then we are getting QR = true
			if l.QR == false {
				continue
			}
			answers := l.Answers

			for _, af := range answers {

				if af.IP != nil {
					ip := af.IP.String()
					if len(ip) <= 16 {
						ipv4 = append(ipv4, ip)
					} else {
						ipv6 = append(ipv6, ip)
					}
				}
			}

			for _, q := range qs {
				//fmt.Println(string(q.Name), q.Type, q.Class)
				cls := q.Type.String()

				if cls == "A" {
					ips = ipv4
				} else if cls == "AAAA" {
					ips = ipv6
				}

				result = append(result, BDNS{"DNS", string(q.Name), q.Type.String(), q.Class.String(), ips})

			}

		}
	}
	if strings.HasPrefix(tcpS.Dest, "10.19.49.") == true {
		return result, nil
	}
	if dnsPacket == false && tcpS.Sport != 0 && onlyDNS == false {
		result = append(result, tcpS)
	}
	return result, nil
}

func StartCapture(device string, stdout bool) {
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
		res, err := ParsePacket(packet, false) // Do something with a packet here.
		if err == nil {
			if len(res) > 0 {
				//fmt.Println(res)
				if !stdout {
					res2json, _ := json.Marshal(res)
					redisdb.RPush("rawpackets", res2json)
				} else {
					switch data := res[0].(type) {
					case BDNS:
						fmt.Println(data.Name, data.Type, data.Class, data.Ips)
					}

				}
			}
		}

	}

}
