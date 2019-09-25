package main

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/go-redis/redis/v7"
	"github.com/kushaldas/bomcapture/pkg/capturing"
)

func ExecuteCommand() {
	redisdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // use default Addr
		Password: "",               // no password set
		DB:       0,                // use default DB
	})

	var command string
	for {

		rawdata := redisdb.BLPop(0, "execute")
		// First get the result of the command
		data, ok := rawdata.Result()
		if ok == nil {
			// We unmarshal once to find out the type of the data
			json.Unmarshal([]byte(data[1]), &command)
		}
		// This cmd can be a security risk
		// TODO: Sanitize the input there.
		fmt.Println(command)
		// Execute here below
		cmd := exec.Command("cowsay", "hello")
		cmd.Run()
	}
}

/*
Entry point for the executable
*/
func main() {
	redisdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // use default Addr
		Password: "",               // no password set
		DB:       0,                // use default DB
	})

	//go ExecuteCommand()

	for {
		var typedData []map[string]interface{}
		var DNSData []capturing.BDNS
		var PacketData []capturing.BPackets
		rawdata := redisdb.BLPop(0, "rawpackets")
		// First get the result of the command
		data, ok := rawdata.Result()
		if ok == nil {
			// We unmarshal once to find out the type of the data
			json.Unmarshal([]byte(data[1]), &typedData)
		}
		for _, eachPacket := range typedData {
			// While sending we are marking the type of the Packet
			res := eachPacket["PacketType"].(string)

			// Process BDNS packets
			if res == "DNS" {
				BDNSBytes := []byte(data[1])
				redisdb.RPush("dnsqueue", BDNSBytes)
				json.Unmarshal(BDNSBytes, &DNSData)
				// TODO: Save to the database
				fmt.Printf("%#v\n", DNSData)
			} else if res == "Packet" {
				PacketBytes := []byte(data[1])
				json.Unmarshal(PacketBytes, &PacketData)
				fmt.Printf("%#v\n", PacketData)
			}
		}

	}
}
