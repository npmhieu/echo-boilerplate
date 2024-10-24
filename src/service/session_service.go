package service

import (
	"goapp/src/config"
	"goapp/src/models"
)

func CreateASessionService(session models.SessionUser) error {
	if err := config.Database().Create(&session).Error; err != nil {
		return err
	}

	return nil
}

func GetSessionByIdService(idSession string) (*models.SessionUser, error) {
	var sessionResult *models.SessionUser

	if err := config.Database().Where("id = ?", idSession).First(&sessionResult).Error; err != nil {
		return nil, err
	}

	return sessionResult, nil
}
