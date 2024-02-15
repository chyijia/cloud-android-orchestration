// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package instances

import (
	"fmt"

	apiv1 "github.com/google/cloud-android-orchestration/api/v1"
	"github.com/google/cloud-android-orchestration/pkg/app/accounts"
)

const DockerIMType IMType = "docker"

type DockerIMConfig struct {
	HostOrchestratorPort int
}

// Docker implementation of the instance manager.
type DockerInstanceManager struct {
	Config Config
}

func NewDockerInstanceManager(cfg Config) *DockerInstanceManager {
	return &DockerInstanceManager{
		Config: cfg,
	}
}

func (m *DockerInstanceManager) ListZones() (*apiv1.ListZonesResponse, error) {
	return nil, fmt.Errorf("%T#ListZones is not implemented", *m)
}

func (m *DockerInstanceManager) CreateHost(_ string, _ *apiv1.CreateHostRequest, _ accounts.User) (*apiv1.Operation, error) {
	return nil, fmt.Errorf("%T#CreateHost is not implemented", *m)
}

func (m *DockerInstanceManager) ListHosts(zone string, user accounts.User, req *ListHostsRequest) (*apiv1.ListHostsResponse, error) {
	return nil, fmt.Errorf("%T#ListHosts is not implemented", *m)
}

func (m *DockerInstanceManager) DeleteHost(zone string, user accounts.User, name string) (*apiv1.Operation, error) {
	return nil, fmt.Errorf("%T#DeleteHost is not implemented", *m)
}

func (m *DockerInstanceManager) WaitOperation(zone string, user accounts.User, name string) (any, error) {
	return nil, fmt.Errorf("%T#WaitOperation is not implemented", *m)
}

func (m *DockerInstanceManager) GetHostClient(zone string, host string) (HostClient, error) {
	return nil, fmt.Errorf("%T#GetHostClient is not implemented", *m)
}
