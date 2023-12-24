package db

import (
	"fmt"

	"hids/config"
	"hids/model"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func initMySQL() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		config.GetConfig().Database.MySQL.User,
		config.GetConfig().Database.MySQL.Password,
		config.GetConfig().Database.MySQL.Host,
		config.GetConfig().Database.MySQL.Port,
		config.GetConfig().Database.MySQL.Name,
	)

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})

	if err != nil {
		log.WithField("error", err).Fatal("Failed to connect to mysql datasource")
	}

	db, err := DB.DB()
	if err != nil {
		log.WithField("error", err).Fatal("Failed to get mysql datasource connection")
	}

	db.SetMaxOpenConns(config.GetConfig().Database.MaxOpenConnections)
	db.SetMaxIdleConns(config.GetConfig().Database.MaxIdleConnections)

	err = DB.AutoMigrate(&model.Rule{}, &model.Expression{})

	if err != nil {
		log.WithField("error", err).Fatal("Failed to auto migrate mysql datasource")
	}
}
