// Copyright 2017 The etcd-operator Authors
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

package k8sutil

import (
	"fmt"
	"os"
	"time"

	api "github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	"github.com/coreos/etcd-operator/pkg/util/constants"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewMemberAddEvent(memberName string, cl *api.EtcdCluster) *v1.Event {
	event := newClusterEvent(cl)
	event.Type = v1.EventTypeNormal
	event.Reason = "New Member Added"
	event.Message = fmt.Sprintf("New member %s added to cluster", memberName)
	return event
}

func MemberRemoveEvent(memberName string, cl *api.EtcdCluster) *v1.Event {
	event := newClusterEvent(cl)
	event.Type = v1.EventTypeNormal
	event.Reason = "Member Removed"
	event.Message = fmt.Sprintf("Existing member %s removed from the cluster", memberName)
	return event
}

func ReplacingDeadMemberEvent(memberName string, cl *api.EtcdCluster) *v1.Event {
	event := newClusterEvent(cl)
	event.Type = v1.EventTypeNormal
	event.Reason = "Replacing Dead Member"
	event.Message = fmt.Sprintf("The dead member %s is being replaced", memberName)
	return event
}

func MemberUpgradedEvent(memberName, oldVersion, newVersion string, cl *api.EtcdCluster) *v1.Event {
	event := newClusterEvent(cl)
	event.Type = v1.EventTypeNormal
	event.Reason = "Member Upgraded"
	event.Message = fmt.Sprintf("Member %s upgraded from %s to %s ", memberName, oldVersion, newVersion)
	return event
}

func newClusterEvent(cl *api.EtcdCluster) *v1.Event {
	t := time.Now()
	return &v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: cl.Name + "-",
			Namespace:    cl.Namespace,
		},
		InvolvedObject: v1.ObjectReference{
			APIVersion:      api.SchemeGroupVersion.String(),
			Kind:            api.EtcdClusterResourceKind,
			Name:            cl.Name,
			Namespace:       cl.Namespace,
			UID:             cl.UID,
			ResourceVersion: cl.ResourceVersion,
		},
		Source: v1.EventSource{
			Component: os.Getenv(constants.EnvOperatorPodName),
		},
		// Each cluster event is unique so it should not be collapsed with other events
		FirstTimestamp: metav1.Time{Time: t},
		LastTimestamp:  metav1.Time{Time: t},
		Count:          int32(1),
	}
}
