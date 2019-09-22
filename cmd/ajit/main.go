package main

import (
	"encoding/json"
	"fmt"

	"github.com/go-redis/redis/v7"
	"github.com/kushaldas/bomcapture/pkg/capturing"
)

/*
Entry point for the executable
*/
func main() {
	redisdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // use default Addr
		Password: "",               // no password set
		DB:       0,                // use default DB
	})

	for {
		var typedData []map[string]interface{}
		var DNSData []capturing.BDNS
		rawdata := redisdb.BLPop(0, "rawpackets")
		// First get the result of the command
		data, ok := rawdata.Result()
		if ok == nil {
			// We unmarshal once to find out the type of the data
			json.Unmarshal([]byte(data[1]), &typedData)
		}
		// While sending we are marking the type of the Packet
		res := typedData[0]["PacketType"].(string)

		// Process BDNS packets
		if res == "DNS" {
			BDNSBytes := []byte(data[1])
			redisdb.RPush("dnsqueue", BDNSBytes)
			json.Unmarshal(BDNSBytes, &DNSData)
			// TODO: Save to the database
			fmt.Printf("%#v\n", DNSData)
		}

	}
}
