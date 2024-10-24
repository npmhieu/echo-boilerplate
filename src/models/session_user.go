package models

import "time"

type SessionUser struct {
	ID          string    `gorm:"primaryKey"`
	SessionData []byte    `gorm:"column:session_data"`
	ExpiresOn   time.Time `gorm:"column:expires_on"` // Đổi thành kiểu time.Time
	Created     time.Time `gorm:"column:created;not null;default:CURRENT_TIMESTAMP"`
	Updated     time.Time `gorm:"column:updated;default:NULL"`
}

// TableName sets a custom table name with prefix tbl_ and single noun.
func (SessionUser) TableName() string {
	return "session_user"
}
