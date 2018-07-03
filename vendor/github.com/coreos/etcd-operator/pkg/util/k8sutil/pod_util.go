// Copyright 2016 The etcd-operator Authors
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
	"encoding/json"
	"fmt"

	api "github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	"github.com/coreos/etcd-operator/pkg/util/etcdutil"

	"k8s.io/api/core/v1"
)

const (
	etcdVolumeName = "etcd-data"
)

func etcdVolumeMounts() []v1.VolumeMount {
	return []v1.VolumeMount{
		{Name: etcdVolumeName, MountPath: etcdVolumeMountDir},
	}
}

func etcdContainer(cmd []string, repo, version string) v1.Container {
	c := v1.Container{
		Command: cmd,
		Name:    "etcd",
		Image:   ImageName(repo, version),
		Ports: []v1.ContainerPort{
			{
				Name:          "server",
				ContainerPort: int32(2380),
				Protocol:      v1.ProtocolTCP,
			},
			{
				Name:          "client",
				ContainerPort: int32(EtcdClientPort),
				Protocol:      v1.ProtocolTCP,
			},
		},
		VolumeMounts: etcdVolumeMounts(),
	}

	return c
}

func containerWithProbes(c v1.Container, lp *v1.Probe, rp *v1.Probe) v1.Container {
	c.LivenessProbe = lp
	c.ReadinessProbe = rp
	return c
}

func containerWithRequirements(c v1.Container, r v1.ResourceRequirements) v1.Container {
	c.Resources = r
	return c
}

func newEtcdProbe(isSecure bool) *v1.Probe {
	// etcd pod is alive only if a linearizable get succeeds.
	cmd := "ETCDCTL_API=3 etcdctl get foo"
	if isSecure {
		tlsFlags := fmt.Sprintf("--cert=%[1]s/%[2]s --key=%[1]s/%[3]s --cacert=%[1]s/%[4]s", operatorEtcdTLSDir, etcdutil.CliCertFile, etcdutil.CliKeyFile, etcdutil.CliCAFile)
		cmd = fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://localhost:%d %s get foo", EtcdClientPort, tlsFlags)
	}
	return &v1.Probe{
		Handler: v1.Handler{
			Exec: &v1.ExecAction{
				Command: []string{"/bin/sh", "-ec", cmd},
			},
		},
		InitialDelaySeconds: 10,
		TimeoutSeconds:      10,
		PeriodSeconds:       60,
		FailureThreshold:    3,
	}
}

func applyPodPolicy(clusterName string, pod *v1.Pod, policy *api.PodPolicy) {
	if policy == nil {
		return
	}

	if policy.Affinity != nil {
		pod.Spec.Affinity = policy.Affinity
	}

	if len(policy.NodeSelector) != 0 {
		pod = PodWithNodeSelector(pod, policy.NodeSelector)
	}
	if len(policy.Tolerations) != 0 {
		pod.Spec.Tolerations = policy.Tolerations
	}

	mergeLabels(pod.Labels, policy.Labels)

	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i] = containerWithRequirements(pod.Spec.Containers[i], policy.Resources)
		if pod.Spec.Containers[i].Name == "etcd" {
			pod.Spec.Containers[i].Env = append(pod.Spec.Containers[i].Env, policy.EtcdEnv...)
		}
	}

	for i := range pod.Spec.InitContainers {
		pod.Spec.InitContainers[i] = containerWithRequirements(pod.Spec.InitContainers[i], policy.Resources)
	}

	for key, value := range policy.Annotations {
		pod.ObjectMeta.Annotations[key] = value
	}
}

// IsPodReady returns false if the Pod Status is nil
func IsPodReady(pod *v1.Pod) bool {
	condition := getPodReadyCondition(&pod.Status)
	return condition != nil && condition.Status == v1.ConditionTrue
}

func getPodReadyCondition(status *v1.PodStatus) *v1.PodCondition {
	for i := range status.Conditions {
		if status.Conditions[i].Type == v1.PodReady {
			return &status.Conditions[i]
		}
	}
	return nil
}

func PodSpecToPrettyJSON(pod *v1.Pod) (string, error) {
	bytes, err := json.MarshalIndent(pod.Spec, "", "    ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
