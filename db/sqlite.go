package db

import (
	"hids/config"
	"hids/model"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func initSQLite() {
	var err error
	DB, err = gorm.Open(sqlite.Open(config.GetConfig().Database.SQLite.Path), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})

	if err != nil {
		log.WithField("error", err).Fatal("Failed to connect to sqlite datasource")
	}

	db, err := DB.DB()
	if err != nil {
		log.WithField("error", err).Fatal("Failed to get sqlite datasource connection")
	}

	db.SetMaxOpenConns(config.GetConfig().Database.MaxOpenConnections)
	db.SetMaxIdleConns(config.GetConfig().Database.MaxIdleConnections)

	err = DB.AutoMigrate(&model.Rule{}, &model.Expression{})

	if err != nil {
		log.WithField("error", err).Fatal("Failed to auto migrate sqlite datasource")
	}
}
