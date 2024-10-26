package service

import (
	"goapp/src/config"
	"goapp/src/models"
)

func CreateAUserService(user models.User) error {
	if err := config.DB.Create(&user).Error; err != nil {
		return err
	}

	return nil
}

func GetUserByMailService(email string) (*models.User, error) {
	var userResult *models.User

	if err := config.DB.Where("email = ?", email).First(&userResult).Error; err != nil {
		return nil, err
	}

	return userResult, nil
}
