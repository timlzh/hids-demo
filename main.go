package main

import (
	"hids/agent"
	"hids/config"
	"hids/db"
)

func main() {
	config.Init()

	db.InitDB()

	ip := "127.0.0.1"
	port := 65530
	agent.Run(ip, port)
}
