package db

import (
	"log"

	"hids/config"
	"hids/model"

	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	switch config.GetConfig().Database.Type {
	case "mysql":
		initMySQL()
	case "sqlite":
		initSQLite()
	default:
		log.Fatal("Invalid datasource selection")
	}

	defaultRules := []model.Rule{
		{
			ID:          1,
			Name:        "Bash Reverse Shell",
			Description: "Bash Reverse Shell",
			Type:        "process",
			Severity:    5,
			IsEnable:    true,
			Expressions: []model.Expression{
				{
					Field:      "cmdline",
					Expression: "bash\\s+-i\\s+>&\\s+/dev/tcp/.*?",
					IsRegex:    true,
				},
			},
		},
		{
			ID:          2,
			Name:        "Python Reverse Shell",
			Description: "Python Reverse Shell",
			Type:        "process",
			Severity:    5,
			IsEnable:    true,
			Expressions: []model.Expression{
				{
					Field:      "cmdline",
					Expression: "python.*?import.*?socket,subprocess,os;.*?",
					IsRegex:    true,
				},
			},
		},
		{
			ID:          3,
			Name:        "Sql Injection",
			Description: "Sql Injection",
			Type:        "network",
			Severity:    2,
			IsEnable:    true,
			Expressions: []model.Expression{
				{
					Field:      "payload",
					Expression: "select.*?from.*?",
					IsRegex:    true,
				},
			},
		},
	}

	for _, rule := range defaultRules {
		DB.Create(&rule)
	}
}
