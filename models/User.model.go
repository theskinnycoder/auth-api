package models

import "gorm.io/gorm"

type User struct {
	gorm.Model `json:"-"`
	Email      string `gorm:"unique" json:"email"`
	Password   string `json:"-"`
}
