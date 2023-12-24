package db

import (
	"log"

	"hids/config"

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
}
