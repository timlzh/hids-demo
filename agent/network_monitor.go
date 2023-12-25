package agent

import (
	"fmt"
	"log"

	"hids/config"

	// pcap "github.com/akrennmair/gopcap"
	pcap "hids/gopcap"
)

// networkMonitorStart
//
//	@param ip string
//	@param port int
func networkMonitorStart() {
	intertfaceName := config.GetConfig().Network.Monitor.Interface

	devices, err := pcap.Findalldevs()
	if err != nil {
		log.Fatal(err)
	}

	var device pcap.Interface
	for _, _device := range devices {
		if _device.Name == intertfaceName {
			device = _device
			break
		}
	}

	if device.Name == "" {
		log.Fatal("No such device")
	}

	log.Printf("Device: %s (%s), ipv4: %s, ipv6: %s\n", device.Name, device.Description, device.Addresses[0].IP.String(), device.Addresses[1].IP.String())

	deviceIP := device.Addresses[0].IP.String()

	handle, err := pcap.Openlive(device.Name, 1024, false, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.Setfilter("tcp or udp and (not broadcast and not multicast)")
	if err != nil {
		log.Fatal(err)
	}

	for {
		pkt := handle.Next()
		if pkt == nil {
			continue
		}

		pkt.Decode()
		packet := getPacketInfo(pkt, deviceIP)
		// log.Println(fmt.Sprintf("Network: %s %s:%s => %s:%s", packet.Protocol, packet.SourceIP, packet.SourcePort, packet.DestIP, packet.DestPort))

		warnings := checkPacket(packet)
		if len(warnings) > 0 {
			for _, warning := range warnings {
				msg := fmt.Sprintf("Warning: %s", warning.Rule.Description)
				msg += fmt.Sprintf("\n\tSeverity: %d", warning.Severity)
				msg += fmt.Sprintf("\n\tNetwork: %s %s:%s => %s:%s", warning.Network.Protocol, warning.Network.SourceIP, warning.Network.SourcePort, warning.Network.DestIP, warning.Network.DestPort)
				msg += fmt.Sprintf("\n\tPID: %d", warning.Process.Pid)
				for _, behavior := range warning.Behaviors {
					msg += fmt.Sprintf("\n\tBehavior: %s", behavior.Value)
				}
				log.Println(msg)
			}
		}
	}
}
