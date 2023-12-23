package main

import (
	"hids/agent"
)

func main() {
	ip := "127.0.0.1"
	port := 65530
	agent.Run(ip, port)
}
