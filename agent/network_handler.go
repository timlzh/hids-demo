package agent

import (
	"fmt"
	"log"

	"hids/api"
	pcap "hids/gopcap"
	"hids/model"
	"hids/utils"
)

// getPacketInfo
//
//	@param pkt *pcap.Packet
//	@param deviceIP string
//	@return packet model.Packet
func getPacketInfo(pkt *pcap.Packet, deviceIP string) model.Packet {
	defer func() {
		if err := recover(); err != nil {
			// log.Println("getPacketInfo panic: ", err)
			return
		}
	}()
	// in or out
	direction := "in"
	if pkt.IP.SrcAddr() == deviceIP {
		direction = "out"
	}

	protocol := "tcp"
	if pkt.IP.Protocol == 17 {
		protocol = "udp"
	}

	packet := model.Packet{
		SourceIP:   pkt.IP.SrcAddr(),
		SourcePort: fmt.Sprintf("%d", pkt.TCP.SrcPort),
		DestIP:     pkt.IP.DestAddr(),
		DestPort:   fmt.Sprintf("%d", pkt.TCP.DestPort),
		Protocol:   protocol,
		Direction:  direction,
		Payload:    string(pkt.Payload),
	}

	return packet
}

// checkPacket
//
//	@param packet model.Packet
//	@return warnings []model.Warning
func checkPacket(packet model.Packet) []model.Warning {
	defer func() {
		if err := recover(); err != nil {
			// log.Println("checkPacket panic: ", err)
			return
		}
	}()

	warnings := []model.Warning{}
	rules, err := api.GetRulesByField("type", "network")
	if err != nil {
		log.Println("error GetRuleByField: ", err)
		return warnings
	}

	for _, rule := range rules {
		result := true
		warning := model.Warning{
			Severity: rule.Severity,
			Type:     rule.Type,
			Network:  packet,
			Rule:     rule,
		}
		for _, expression := range rule.Expressions {
			switch expression.Field {
			case "source_ip":
				result = result && utils.CheckExpression(expression, packet.SourceIP)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: packet.SourceIP,
				})
			case "source_port":
				result = result && utils.CheckExpression(expression, packet.SourcePort)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: packet.SourcePort,
				})
			case "dest_ip":
				result = result && utils.CheckExpression(expression, packet.DestIP)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: packet.DestIP,
				})
			case "dest_port":
				result = result && utils.CheckExpression(expression, packet.DestPort)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: packet.DestPort,
				})
			case "protocol":
				result = result && utils.CheckExpression(expression, packet.Protocol)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: packet.Protocol,
				})
			case "direction":
				result = result && utils.CheckExpression(expression, packet.Direction)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: packet.Direction,
				})
			case "payload":
				result = result && utils.CheckExpression(expression, packet.Payload)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: packet.Payload,
				})
			}

			if !result {
				break
			}
		}
		if result {
			warnings = append(warnings, warning)
		}
	}

	return warnings
}
