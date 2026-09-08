package database

import (
	"fmt"
	"log"
	"time"

	"construct/delivery/internal/config"
	"construct/delivery/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Init(cfg *config.Config) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPass, cfg.DBName)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	if sqlDB, err := DB.DB(); err == nil {
		sqlDB.SetMaxOpenConns(50)
		sqlDB.SetMaxIdleConns(10)
		sqlDB.SetConnMaxLifetime(30 * time.Minute)
	}

	DB.AutoMigrate(
		&models.SendingDomain{},
		&models.APIKey{},
		&models.Message{},
		&models.MessageEvent{},
		&models.Template{},
		&models.Suppression{},
		&models.Notification{},
		&models.NotificationPreference{},
		&models.WebPushSubscription{},
		&models.DeviceToken{},
	)

	log.Println("[db] Connected and migrated")
}
