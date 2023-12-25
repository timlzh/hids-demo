package agent

import (
	"hids/agent/network"
	"hids/agent/process"
)

func Run(ip string, port int) {
	go process.MonitorStart(ip, port)
	network.MonitorStart()
}
