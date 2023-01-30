/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package models

import (
	helper "github.com/apache/incubator-devlake/helpers/pluginhelper/api"
)

// This object conforms to what the frontend currently sends.
type AzureConnection struct {
	helper.BaseConnection `mapstructure:",squash"`
	helper.RestConnection `mapstructure:",squash"`
	helper.BasicAuth      `mapstructure:",squash"`
}

type AzureResponse struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	AzureConnection
}

type TestConnectionRequest struct {
	Endpoint string `json:"endpoint" validate:"required"`
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
	Proxy    string `json:"proxy"`
}

func (AzureConnection) TableName() string {
	return "_tool_azure_connections"
}
