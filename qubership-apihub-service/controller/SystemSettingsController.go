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

package controller

import (
	"net/http"

	"github.com/Netcracker/qubership-apihub-backend/qubership-apihub-service/service"
	"github.com/Netcracker/qubership-apihub-backend/qubership-apihub-service/view"
)

type SystemSettingsController interface {
	GetVersionPattern(w http.ResponseWriter, r *http.Request)
	UpdateVersionPattern(w http.ResponseWriter, r *http.Request)
}

func NewSystemSettingsController(service service.SystemSettingsService) SystemSettingsController {
	return &systemSettingsControllerImpl{service: service}
}

type systemSettingsControllerImpl struct {
	service service.SystemSettingsService
}

func (c *systemSettingsControllerImpl) GetVersionPattern(w http.ResponseWriter, r *http.Request) {
	config, err := c.service.GetVersionPattern()
	if err != nil {
		RespondWithCustomError(w, err)
		return
	}
	RespondWithJson(w, http.StatusOK, config)
}

func (c *systemSettingsControllerImpl) UpdateVersionPattern(w http.ResponseWriter, r *http.Request) {
	var req view.UpdateVersionPatternReq
	err := ReadJsonFromRequestBody(r, &req)
	if err != nil {
		RespondWithCustomError(w, err)
		return
	}

	userId := GetUserIdFromContext(r)
	config, err := c.service.UpdateVersionPattern(req.Pattern, userId)
	if err != nil {
		RespondWithCustomError(w, err)
		return
	}

	RespondWithJson(w, http.StatusOK, config)
}
