// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"net/http"
	"regexp"
	"time"

	"github.com/Netcracker/qubership-apihub-backend/qubership-apihub-service/entity"
	"github.com/Netcracker/qubership-apihub-backend/qubership-apihub-service/exception"
	"github.com/Netcracker/qubership-apihub-backend/qubership-apihub-service/repository"
	"github.com/Netcracker/qubership-apihub-backend/qubership-apihub-service/view"
)

const (
	VERSION_PATTERN_KEY     = "versionPattern"
	DEFAULT_VERSION_PATTERN = `^(?!\s)(?=.*\S)[A-Za-z0-9_.\-~ ]+(?<!\s)$`
)

type SystemSettingsService interface {
	GetVersionPattern() (*view.VersionPatternConfig, error)
	UpdateVersionPattern(pattern string, userId string) (*view.VersionPatternConfig, error)
	ValidateVersionName(versionName string) error
}

func NewSystemSettingsService(repo repository.SystemSettingsRepository) SystemSettingsService {
	return &systemSettingsServiceImpl{
		repo: repo,
	}
}

type systemSettingsServiceImpl struct {
	repo repository.SystemSettingsRepository
}

func (s *systemSettingsServiceImpl) GetVersionPattern() (*view.VersionPatternConfig, error) {
	setting, err := s.repo.GetSetting(VERSION_PATTERN_KEY)
	if err != nil {
		return nil, err
	}

	pattern := DEFAULT_VERSION_PATTERN
	if setting != nil && setting.Value != "" {
		pattern = setting.Value
	}

	return &view.VersionPatternConfig{
		Pattern: pattern,
	}, nil
}

func (s *systemSettingsServiceImpl) UpdateVersionPattern(pattern string, userId string) (*view.VersionPatternConfig, error) {
	// Validate that the pattern is a valid regex
	_, err := regexp.Compile(pattern)
	if err != nil {
		return nil, &exception.CustomError{
			Status:  http.StatusBadRequest,
			Code:    exception.InvalidVersionPatternFormat,
			Message: exception.InvalidVersionPatternFormatMsg,
			Params:  map[string]interface{}{"pattern": pattern},
			Debug:   err.Error(),
		}
	}

	setting := &entity.SystemSettingsEntity{
		Key:       VERSION_PATTERN_KEY,
		Value:     pattern,
		UpdatedAt: time.Now(),
		UpdatedBy: userId,
	}

	err = s.repo.UpsertSetting(setting)
	if err != nil {
		return nil, err
	}

	return &view.VersionPatternConfig{
		Pattern: pattern,
	}, nil
}

func (s *systemSettingsServiceImpl) ValidateVersionName(versionName string) error {
	config, err := s.GetVersionPattern()
	if err != nil {
		return err
	}

	versionNameRegexp, err := regexp.Compile(config.Pattern)
	if err != nil {
		// This shouldn't happen as we validate on save, but handle it anyway
		return err
	}

	if !versionNameRegexp.MatchString(versionName) {
		return &exception.CustomError{
			Status:  http.StatusBadRequest,
			Code:    exception.VersionDoesntMatchPattern,
			Message: exception.VersionDoesntMatchPatternMsg,
			Params:  map[string]interface{}{"version": versionName, "pattern": config.Pattern},
		}
	}

	return nil
}
