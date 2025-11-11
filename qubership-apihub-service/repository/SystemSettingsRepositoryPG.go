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

package repository

import (
	"github.com/Netcracker/qubership-apihub-backend/qubership-apihub-service/db"
	"github.com/Netcracker/qubership-apihub-backend/qubership-apihub-service/entity"
	"github.com/go-pg/pg/v10"
)

func NewSystemSettingsRepositoryPG(cp db.ConnectionProvider) (SystemSettingsRepository, error) {
	return &systemSettingsRepositoryImpl{cp: cp}, nil
}

type systemSettingsRepositoryImpl struct {
	cp db.ConnectionProvider
}

func (r systemSettingsRepositoryImpl) GetSetting(key string) (*entity.SystemSettingsEntity, error) {
	result := &entity.SystemSettingsEntity{}
	err := r.cp.GetConnection().Model(result).
		Where("key = ?", key).
		Select()
	if err != nil {
		if err == pg.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return result, nil
}

func (r systemSettingsRepositoryImpl) UpsertSetting(setting *entity.SystemSettingsEntity) error {
	_, err := r.cp.GetConnection().Model(setting).
		OnConflict("(key) DO UPDATE").
		Set("value = EXCLUDED.value").
		Set("updated_at = EXCLUDED.updated_at").
		Set("updated_by = EXCLUDED.updated_by").
		Insert()
	return err
}
