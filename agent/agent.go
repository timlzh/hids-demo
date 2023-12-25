package agent

import (
	"hids/agent/file"
	"hids/agent/network"
	"hids/agent/process"
)

func Run(ip string, port int) {
	go process.MonitorStart(ip, port)
	go network.MonitorStart()
	go file.MonitorStart()

	// Block forever
	select {}
}
