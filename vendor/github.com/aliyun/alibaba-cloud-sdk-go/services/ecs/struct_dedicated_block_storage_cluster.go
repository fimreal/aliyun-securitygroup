package ecs

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

// DedicatedBlockStorageCluster is a nested struct in ecs response
type DedicatedBlockStorageCluster struct {
	Status                               string                               `json:"Status" xml:"Status"`
	Type                                 string                               `json:"Type" xml:"Type"`
	Description                          string                               `json:"Description" xml:"Description"`
	ExpiredTime                          string                               `json:"ExpiredTime" xml:"ExpiredTime"`
	CreateTime                           string                               `json:"CreateTime" xml:"CreateTime"`
	ZoneId                               string                               `json:"ZoneId" xml:"ZoneId"`
	Category                             string                               `json:"Category" xml:"Category"`
	DedicatedBlockStorageClusterName     string                               `json:"DedicatedBlockStorageClusterName" xml:"DedicatedBlockStorageClusterName"`
	DedicatedBlockStorageClusterId       string                               `json:"DedicatedBlockStorageClusterId" xml:"DedicatedBlockStorageClusterId"`
	DedicatedBlockStorageClusterCapacity DedicatedBlockStorageClusterCapacity `json:"DedicatedBlockStorageClusterCapacity" xml:"DedicatedBlockStorageClusterCapacity"`
}
