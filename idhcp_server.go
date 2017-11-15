package main

import (
	dhcp "github.com/krolaw/dhcp4"


	"log"
	"math/rand"
	"net"
	"time"

	"github.com/krolaw/dhcp4/conn"
	"os"

	"github.com/go-redis/redis"
	"github.com/spf13/viper"
	"strconv"
	"fmt"
)

var dhcp_options = []string{"config:dhcp:start", "config:dhcp:leaseDuration", "config:dhcp:leaseRange", "config:dhcp:subnetMask"}

type DhcpConfig struct {
	start net.IP
	leaseDuration time.Duration
	leaseRange int
	subnetMask net.IP
}

func main() {

	viper.SetDefault("redisAddr", "127.0.0.1:6379")
	viper.SetDefault("redisPw", "")
	viper.SetDefault("redisDb", 0)

	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/iserv/")
	viper.AddConfigPath("$HOME/.iserv")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error reading config file %s \n", err))
	}

	client := redis.NewClient(&redis.Options{
		Addr: viper.GetString("redisAddr"),
		Password: viper.GetString("redisPw"),
		DB: viper.GetInt("redisDb"),
	})

	settingIp, err := client.Get("config:ip").Result()

	if err == redis.Nil {
		settingIp = "172.16.0.1"
		client.Set("config:ip", settingIp, 0).Result()
		log.Print("Could not read config from redis")
	} else {
		log.Print("Config read from redis")
	}

	settingIf, err := client.Get("config:if").Result()

	if err == redis.Nil {
		settingIf = ""
		client.Set("config:if", settingIf, 0).Result()
	}

	dhcpConfig, err := client.MGet(dhcp_options...).Result()
	var config DhcpConfig
	if err != redis.Nil {
		var start net.IP
		if dhcpConfig[0] != nil {
			start = net.ParseIP(dhcpConfig[0].(string))
		} else {
			start = net.IPv4(172, 16, 0, 2)
			client.Set(dhcp_options[1], start.String(), 0).Result()
		}
		var duration time.Duration
		if dhcpConfig[1] != nil {
			duration, err = time.ParseDuration(dhcpConfig[1].(string))
			if err != nil {
				duration = time.Hour * 2
				client.Set(dhcp_options[1], duration.String(), 0).Result()
			}
		} else {
			duration = time.Hour * 2
			client.Set(dhcp_options[1], duration.String(), 0).Result()
		}
		var leaseRange uint64
		if dhcpConfig[2] != nil {
			leaseRange, err = strconv.ParseUint(dhcpConfig[2].(string), 10, 32)
		} else {
			leaseRange = 20
			client.Set(dhcp_options[2], leaseRange, 0).Result()
		}
		var subnetMask net.IP
		if dhcpConfig[3] != nil {
			subnetMask = net.ParseIP(dhcpConfig[3].(string))
		} else {
			subnetMask = net.IPv4(255, 255, 255, 0)
			client.Set(dhcp_options[3], subnetMask.String(), 0).Result()
		}

		config = DhcpConfig{
			start:start,
			leaseDuration: duration,
			leaseRange:int(leaseRange),
			subnetMask:subnetMask,
			}
	}

	serverIp := net.ParseIP(settingIp).To4()
	handler := &DHCPHandler {
		ip: serverIp,
		leaseDuration: config.leaseDuration,
		start: config.start,
		leaseRange: config.leaseRange,
		leases: make(map[int]lease, 10),
		options: dhcp.Options {
			dhcp.OptionSubnetMask: []byte(config.subnetMask),
			dhcp.OptionRouter: []byte(serverIp),
			dhcp.OptionDomainNameServer: []byte(serverIp),
		},
		client: client,
	}
	con, err := conn.NewUDP4BoundListener(settingIf, "0.0.0.0:67")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	log.Fatal(dhcp.Serve(con, handler))
}

type lease struct {
	nic string
	expiry time.Time
}

type DHCPHandler struct {
	ip net.IP
	options dhcp.Options
	start net.IP
	leaseRange int
	leaseDuration time.Duration
	leases map[int]lease
	client *redis.Client
}

func (h *DHCPHandler) ServeDHCP(p dhcp.Packet, msgType dhcp.MessageType, options dhcp.Options) (d dhcp.Packet) {
	log.Print("Incoming packet from ", p.CHAddr().String(), " of type ", dhcp.MessageType(msgType).String())
	switch msgType {

	case dhcp.Discover:
		free, nic := -1, p.CHAddr().String()
		for i, v := range h.leases { // Find previous lease
			if v.nic == nic {
				free = i
				goto reply
			}
		}
		if free = h.freeLease(); free == -1 {
			return
		}
	reply:
		ip := dhcp.IPAdd(h.start, free)
		log.Print(h.ip.String())
		log.Print("Sending offer with ", ip.String())
		return dhcp.ReplyPacket(p, dhcp.Offer, h.ip, ip, h.leaseDuration,
			h.options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))

	case dhcp.Request:
		log.Println("Handling request...")
		server, ok := options[dhcp.OptionServerIdentifier]
		if ok && !net.IP(server).Equal(h.ip) {
			return nil // Message not for this dhcp server
		}
		reqIP := net.IP(options[dhcp.OptionRequestedIPAddress])
		if reqIP == nil {
			reqIP = net.IP(p.CIAddr())
		}

		log.Println("Request incoming for: ", reqIP.String())


		if len(reqIP) == 4 && !reqIP.Equal(net.IPv4zero) {
			if leaseNum := dhcp.IPRange(h.start, reqIP) - 1; leaseNum >= 0 && leaseNum < h.leaseRange {
				if l, exists := h.leases[leaseNum]; !exists || l.nic == p.CHAddr().String() {
					clientB, ok := options[dhcp.OptionHostName]
					if ok {
						client := string(clientB)
						key := "record:" + reqIP.String() + ":" + client + ":A"
						_, e := h.client.HSet(key, "type", "A").Result()
						if  e != nil {
							log.Fatalln("Could not write to redis", e)
						}
						_, e = h.client.HSet(key, "host", reqIP.String()).Result()
						if  e != nil {
							log.Fatalln("Could not write to redis", e)
						}
					}
					h.leases[leaseNum] = lease{nic: p.CHAddr().String(), expiry: time.Now().Add(h.leaseDuration)}
					_, e := h.client.HSet("machine:" + reqIP.String(), "mac", p.CHAddr().String()).Result()
					if e != nil {
						log.Fatalln("Could not write to redis", e)
					}
					return dhcp.ReplyPacket(p, dhcp.ACK, h.ip, reqIP, h.leaseDuration,
						h.options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
				}
			}
		}
		return dhcp.ReplyPacket(p, dhcp.NAK, h.ip, nil, 0, nil)

	case dhcp.Release, dhcp.Decline:
		nic := p.CHAddr().String()
		//TODO delete records from database
		for i, v := range h.leases {
			if v.nic == nic {
				delete(h.leases, i)
				break
			}
		}
	}
	return nil
}

func (h *DHCPHandler) freeLease() int {
	now := time.Now()
	b := rand.Intn(h.leaseRange) // Try random first
	for _, v := range [][]int{[]int{b, h.leaseRange}, []int{0, b}} {
		for i := v[0]; i < v[1]; i++ {
			if l, ok := h.leases[i]; !ok || l.expiry.Before(now) {
				return i
			}
		}
	}
	return -1
}