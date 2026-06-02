package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/HeadStone1/s-ui/config"
	"github.com/HeadStone1/s-ui/database/model"
	"github.com/HeadStone1/s-ui/util/common"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

func initUser() error {
	var count int64
	err := db.Model(&model.User{}).Count(&count).Error
	if err != nil {
		return err
	}
	if count == 0 {
		password := common.Random(24)
		passwordHash, err := common.HashPassword(password)
		if err != nil {
			return err
		}
		user := &model.User{
			Username:     "admin",
			PasswordHash: passwordHash,
		}
		if err := db.Create(user).Error; err != nil {
			return err
		}
		fmt.Println("Generated initial admin credentials:")
		fmt.Println("Username: admin")
		fmt.Println("Password:", password)
		fmt.Println("Save this password now. It will not be shown again.")
	}
	return nil
}

func migrateSecrets() error {
	var users []model.User
	if err := db.Model(&model.User{}).Find(&users).Error; err != nil {
		return err
	}
	for _, user := range users {
		password := user.Password
		if user.PasswordHash == "" && password != "" {
			if user.Username == "admin" && password == "admin" {
				password = common.Random(24)
				fmt.Println("Replaced insecure admin/admin credentials during migration:")
				fmt.Println("Username: admin")
				fmt.Println("Password:", password)
				fmt.Println("Save this password now. It will not be shown again.")
			}
			hash, err := common.HashPassword(password)
			if err != nil {
				return err
			}
			if err := db.Model(&model.User{}).Where("id = ?", user.Id).Updates(map[string]interface{}{
				"password_hash": hash,
				"password":      "",
			}).Error; err != nil {
				return err
			}
		}
	}

	var tokens []model.Tokens
	if err := db.Model(&model.Tokens{}).Find(&tokens).Error; err != nil {
		return err
	}
	for _, token := range tokens {
		updates := map[string]interface{}{}
		if token.TokenHash == "" && token.Token != "" {
			updates["token_hash"] = common.HashToken(token.Token)
			updates["token"] = ""
		}
		if token.Scope == "" {
			updates["scope"] = "read"
		}
		if token.Expiry == 0 {
			updates["expiry"] = time.Now().Add(30 * 24 * time.Hour).Unix()
		}
		if len(updates) > 0 {
			if err := db.Model(&model.Tokens{}).Where("id = ?", token.Id).Updates(updates).Error; err != nil {
				return err
			}
		}
	}

	var clients []model.Client
	if err := db.Model(&model.Client{}).Where("sub_secret = '' OR sub_secret IS NULL").Find(&clients).Error; err != nil {
		return err
	}
	for _, client := range clients {
		if err := db.Model(&model.Client{}).Where("id = ?", client.Id).Update("sub_secret", common.Random(32)).Error; err != nil {
			return err
		}
	}
	return nil
}

func OpenDB(dbPath string) error {
	dir := path.Dir(dbPath)
	err := os.MkdirAll(dir, 01740)
	if err != nil {
		return err
	}

	var gormLogger logger.Interface

	if config.IsDebug() {
		gormLogger = logger.Default
	} else {
		gormLogger = logger.Discard
	}

	c := &gorm.Config{
		Logger: gormLogger,
	}
	sep := "?"
	if strings.Contains(dbPath, "?") {
		sep = "&"
	}
	dsn := dbPath + sep + "_busy_timeout=10000&_journal_mode=WAL"
	db, err = gorm.Open(sqlite.Open(dsn), c)
	if err != nil {
		return err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if config.IsDebug() {
		db = db.Debug()
	}
	return nil
}

func InitDB(dbPath string) error {
	err := OpenDB(dbPath)
	if err != nil {
		return err
	}

	// Default Outbounds
	if !db.Migrator().HasTable(&model.Outbound{}) {
		db.Migrator().CreateTable(&model.Outbound{})
		defaultOutbound := []model.Outbound{
			{Type: "direct", Tag: "direct", Options: json.RawMessage(`{}`)},
		}
		db.Create(&defaultOutbound)
	}

	err = db.AutoMigrate(
		&model.Setting{},
		&model.Tls{},
		&model.Inbound{},
		&model.Outbound{},
		&model.Service{},
		&model.Endpoint{},
		&model.User{},
		&model.Tokens{},
		&model.Stats{},
		&model.Client{},
		&model.Changes{},
	)
	if err != nil {
		return err
	}
	err = migrateSecrets()
	if err != nil {
		return err
	}
	err = initUser()
	if err != nil {
		return err
	}

	return nil
}

func GetDB() *gorm.DB {
	return db
}

func IsNotFound(err error) bool {
	return err == gorm.ErrRecordNotFound
}
