package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"database/sql"

	"github.com/go-redis/redis/v7"
	"github.com/kushaldas/bomcapture/pkg/capturing"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
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
	// The following is for configuration using viper
	viper.SetConfigName("db")
	viper.AddConfigPath("./")
	err := viper.ReadInConfig()

	if err != nil {
		fmt.Println("No configuration file loaded - exiting")
		return
	}

	connStr := fmt.Sprintf("postgresql://%s:%s@127.0.0.1/bomkesh", viper.Get("user"), viper.Get("password"))
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

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
				// Now save the IP results to the redis for quick recovery
				d := DNSData[0]
				for _, ip := range d.Ips {
					rname := fmt.Sprintf("ip:%s", ip)
					redisdb.SAdd(rname, d.Name)
					_, err := db.Exec("INSERT INTO dnsqueue(domain_name, domain_class, domain_type, ip, timestamp) VALUES ($1, $2, $3, $4, $5)", d.Name, d.Class, d.Type, ip, time.Now())
					if err != nil {
						fmt.Printf("%#v\n", err)
						panic(err)
					}
				}
				// TODO: Save to the database
				fmt.Printf("%#v\n", DNSData)
			} else if res == "Packet" {
				PacketBytes := []byte(data[1])
				json.Unmarshal(PacketBytes, &PacketData)
				//fmt.Printf("%#v\n", PacketData)
				p := PacketData[0]

				_, err := db.Exec("INSERT INTO tcppacket(source_ip, destination_ip, source_port, destination_port, timestamp) VALUES ($1, $2, $3, $4, $5)", p.Src, p.Dest, p.Sport, p.Dport, time.Now())
				if err != nil {
					fmt.Printf("%#v\n", err)
					panic(err)
				}
			}
		}

	}
}
