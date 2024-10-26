package models

import (
	"time"
)

type User struct {
	ID         uint      `gorm:"primaryKey;column:id"`
	Created    time.Time `gorm:"column:created;not null;default:CURRENT_TIMESTAMP"`
	Updated    time.Time `gorm:"column:updated"`
	Email      string    `gorm:"column:email;not null;unique"`
	Password   string    `gorm:"column:password;not null"`
	FullName   string    `gorm:"column:fullName;not null"`
	Phone      string    `gorm:"column:phone"`
	RoleMask   int       `gorm:"column:roleMask"`
	IsVerified bool      `gorm:"column:isVerified"`
}

// TableName sets a custom table name with prefix tbl_ and single noun.
func (User) TableName() string {
	return "tbl_user"
}
