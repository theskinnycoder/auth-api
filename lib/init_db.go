package lib

import (
	"fmt"

	"github.com/theskinnycoder/auth-api/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	if conn, err := gorm.Open(mysql.Open("5ph17c85qsvq:pscale_pw_sZCQOLi9OzvKOz6-CVH6AnolZka2IXMS1pFI8wGVYzI@tcp(dwkl4a7jrvsc.ap-south-2.psdb.cloud)/auth-api?tls=true&parseTime=true"), &gorm.Config{}); err != nil {
		panic("failed to connect to the database")
	} else {
		conn.AutoMigrate(&models.User{})
		DB = conn
	}
	fmt.Println("Initializing DB")
}
