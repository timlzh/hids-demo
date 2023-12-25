package main

import (
	"log"

	"hids/agent"
	"hids/api"
	"hids/config"
	"hids/db"
	"hids/webui"
)

func main() {
	config.Init()

	db.InitDB()

	err := api.ReadRuleFromJson(config.GetConfig().Rule.Path)
	if err != nil {
		log.Fatal("error ReadRuleFromJson: ", err)
	}

	ip := "127.0.0.1"
	port := 65530
	go agent.Run(ip, port)

	webui.Run()
}
