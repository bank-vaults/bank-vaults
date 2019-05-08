// Copyright © 2019 Banzai Cloud
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

package vault

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	vaultv1alpha1 "github.com/banzaicloud/bank-vaults/operator/pkg/apis/vault/v1alpha1"
	"github.com/banzaicloud/bank-vaults/pkg/kv/k8s"
	bvtls "github.com/banzaicloud/bank-vaults/pkg/tls"
	"github.com/banzaicloud/bank-vaults/pkg/vault"
	etcdv1beta2 "github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	"github.com/coreos/etcd-operator/pkg/util/etcdutil"
	monitorv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/hashicorp/vault/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_vault")

// Add creates a new Vault Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileVault{client: mgr.GetClient(), scheme: mgr.GetScheme(), httpClient: newHTTPClient()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("vault-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Vault
	err = c.Watch(&source.Kind{Type: &vaultv1alpha1.Vault{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileVault{}

// ReconcileVault reconciles a Vault object
type ReconcileVault struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client     client.Client
	scheme     *runtime.Scheme
	httpClient *http.Client
}

func (r *ReconcileVault) createOrUpdateObject(o runtime.Object) error {
	key, err := client.ObjectKeyFromObject(o)
	if err != nil {
		return err
	}

	current := o.DeepCopyObject()

	err = r.client.Get(context.TODO(), key, current)
	if apierrors.IsNotFound(err) {
		return r.client.Create(context.TODO(), o)
	} else if err == nil {
		resourceVersion := current.(metav1.ObjectMetaAccessor).GetObjectMeta().GetResourceVersion()
		o.(metav1.ObjectMetaAccessor).GetObjectMeta().SetResourceVersion(resourceVersion)

		// Handle special cases for update
		switch o.(type) {
		case *corev1.Service:
			svc := o.(*corev1.Service)
			svc.Spec.ClusterIP = current.(*corev1.Service).Spec.ClusterIP
			// Preserve the annotation when updating the service
			svc.Annotations = current.(*corev1.Service).Annotations
		}

		return r.client.Update(context.TODO(), o)
	}

	return err
}

func (r *ReconcileVault) createObjectIfNotExists(o runtime.Object) error {
	key, err := client.ObjectKeyFromObject(o)
	if err != nil {
		return err
	}

	current := o.DeepCopyObject()

	err = r.client.Get(context.TODO(), key, current)
	if apierrors.IsNotFound(err) {
		return r.client.Create(context.TODO(), o)
	}

	return err
}

// Reconcile reads that state of the cluster for a Vault object and makes changes based on the state read
// and what is in the Vault.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileVault) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Vault")

	// Fetch the Vault instance
	v := &vaultv1alpha1.Vault{}
	err := r.client.Get(context.TODO(), request.NamespacedName, v)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// check if we need to create an etcd cluster
	// if etcd size is < 0. Will not create etcd cluster
	if v.Spec.GetStorageType() == "etcd" && v.Spec.GetEtcdSize() > 0 {
		etcdCluster, err := etcdForVault(v)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to fabricate etcd cluster: %v", err)
		}

		// Create the secret if it doesn't exist
		sec, err := secretForEtcd(etcdCluster)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to fabricate secret for etcd: %v", err)
		}

		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, sec, r.scheme); err != nil {
			return reconcile.Result{}, err
		}

		err = r.createObjectIfNotExists(sec)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create secret for etcd: %v", err)
		}

		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, etcdCluster, r.scheme); err != nil {
			return reconcile.Result{}, err
		}

		err = r.createOrUpdateObject(etcdCluster)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create/update etcd cluster: %v", err)
		}
	}

	if !v.Spec.GetTLSDisable() {
		// Create the secret if it doesn't exist
		sec, err := secretForVault(v)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to fabricate secret for vault: %v", err)
		}

		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, sec, r.scheme); err != nil {
			return reconcile.Result{}, err
		}

		err = r.createObjectIfNotExists(sec)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create secret for vault: %v", err)
		}
	}

	if v.Spec.IsFluentDEnabled() {
		cm := configMapForFluentD(v)

		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, cm, r.scheme); err != nil {
			return reconcile.Result{}, err
		}

		err = r.createOrUpdateObject(cm)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create/update fluentd configmap: %v", err)
		}
	}

	if !v.Spec.IsStatsdDisabled() {
		// Create the configmap if it doesn't exist
		cm := configMapForStatsD(v)

		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, cm, r.scheme); err != nil {
			return reconcile.Result{}, err
		}

		err = r.createOrUpdateObject(cm)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create/update statsd configmap: %v", err)
		}
	}

	// Create the StatefulSet if it doesn't exist
	statefulSet, err := statefulSetForVault(v)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to fabricate StatefulSet: %v", err)
	}

	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, statefulSet, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	err = r.createOrUpdateObject(statefulSet)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create/update StatefulSet: %v", err)
	}

	if v.Spec.ServiceMonitorEnabled {
		// Create the ServiceMonitor if it doesn't exist
		serviceMonitor := serviceMonitorForVault(v)
		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, serviceMonitor, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		err = r.createOrUpdateObject(serviceMonitor)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create/update serviceMonitor: %v", err)
		}
	}

	// Create the service if it doesn't exist
	ser := serviceForVault(v)
	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, ser, r.scheme); err != nil {
		return reconcile.Result{}, err
	}
	err = r.createOrUpdateObject(ser)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create/update service: %v", err)
	}

	// Create the service if it doesn't exist
	// NOTE: currently this is not used, but should be here once we implement support for Client Forwarding as well.
	// Currently request forwarding works only.
	services := perInstanceServicesForVault(v)
	for _, ser := range services {
		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, ser, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		err = r.createOrUpdateObject(ser)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create/update per instance service: %v", err)
		}
	}

	// Create the configmap if it doesn't exist
	cm := configMapForConfigurer(v)

	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, cm, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	err = r.createOrUpdateObject(cm)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create/update configurer configmap: %v", err)
	}

	externalConfigMaps := corev1.ConfigMapList{}
	externalConfigMapsFilter := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelsForVaultConfigurer(v.Name)),
	}
	if err = r.client.List(context.TODO(), &externalConfigMapsFilter, &externalConfigMaps); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list configmaps: %v", err)
	}

	externalSecrets := corev1.SecretList{}
	externalSecretsFilter := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelsForVaultConfigurer(v.Name)),
	}
	if err = r.client.List(context.TODO(), &externalSecretsFilter, &externalSecrets); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list secrets: %v", err)
	}

	// Create the deployment if it doesn't exist
	configurerDep := deploymentForConfigurer(v, externalConfigMaps, externalSecrets)
	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, configurerDep, r.scheme); err != nil {
		return reconcile.Result{}, err
	}
	err = r.createOrUpdateObject(configurerDep)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create/update configurer deployment: %v", err)
	}

	// Create the Configurer service if it doesn't exist
	configurerSer := serviceForVaultConfigurer(v)
	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, configurerSer, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	err = r.createOrUpdateObject(configurerSer)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create/update service: %v", err)
	}

	// Create ingress if specificed
	if ingress := ingressForVault(v); ingress != nil {
		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, ingress, r.scheme); err != nil {
			return reconcile.Result{}, err
		}

		err = r.createOrUpdateObject(ingress)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create/update ingress: %v", err)
		}
	}

	// Update the Vault status with the pod names
	podList := podList()
	labelSelector := labels.SelectorFromSet(labelsForVault(v.Name))
	listOps := &client.ListOptions{LabelSelector: labelSelector}
	err = r.client.List(context.TODO(), listOps, podList)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list pods: %v", err)
	}
	podNames := getPodNames(podList.Items)

	var leader string
	for _, podName := range podNames {
		url := fmt.Sprintf("%s://%s.%s:8200/v1/sys/health", strings.ToLower(string(getVaultURIScheme(v))), podName, v.Namespace)
		resp, err := r.httpClient.Get(url)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				leader = podName
				break
			}
		}
	}

	if !reflect.DeepEqual(podNames, v.Status.Nodes) || !reflect.DeepEqual(leader, v.Status.Leader) {
		v.Status.Nodes = podNames
		v.Status.Leader = leader
		err := r.client.Update(context.TODO(), v)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update vault status: %v", err)
		}
	}

	return reconcile.Result{}, nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func secretForEtcd(e *etcdv1beta2.EtcdCluster) (*corev1.Secret, error) {
	hosts := []string{
		e.Name,
		e.Name + "." + e.Namespace,
		"*." + e.Name + "." + e.Namespace + ".svc",
		e.Name + "-client." + e.Namespace + ".svc",
		"localhost",
	}
	chain, err := bvtls.GenerateTLS(strings.Join(hosts, ","), "8760h")
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
	}
	secret.Name = e.Name + "-tls"
	secret.Namespace = e.Namespace
	secret.Labels = labelsForVault(e.Name)
	secret.StringData = map[string]string{}

	secret.StringData[etcdutil.CliCAFile] = chain.CACert
	secret.StringData[etcdutil.CliCertFile] = chain.ClientCert
	secret.StringData[etcdutil.CliKeyFile] = chain.ClientKey

	secret.StringData["peer-ca.crt"] = chain.CACert
	secret.StringData["peer.crt"] = chain.PeerCert
	secret.StringData["peer.key"] = chain.PeerKey

	secret.StringData["server-ca.crt"] = chain.CACert
	secret.StringData["server.crt"] = chain.ServerCert
	secret.StringData["server.key"] = chain.ServerKey

	return secret, nil
}

func etcdForVault(v *vaultv1alpha1.Vault) (*etcdv1beta2.EtcdCluster, error) {
	storage := v.Spec.GetStorage()
	etcdAddress := storage["address"].(string)
	etcdURL, err := url.Parse(etcdAddress)
	if err != nil {
		return nil, err
	}
	etcdName := etcdURL.Hostname()
	etcdCluster := &etcdv1beta2.EtcdCluster{}
	etcdCluster.APIVersion = etcdv1beta2.SchemeGroupVersion.String()
	etcdCluster.Kind = etcdv1beta2.EtcdClusterResourceKind
	etcdCluster.Annotations = v.Spec.EtcdAnnotations
	etcdCluster.Name = etcdName
	etcdCluster.Namespace = v.Namespace
	etcdCluster.Labels = labelsForVault(v.Name)
	etcdCluster.Spec.Size = v.Spec.GetEtcdSize()
	etcdCluster.Spec.Pod = &etcdv1beta2.PodPolicy{
		PersistentVolumeClaimSpec: v.Spec.EtcdPVCSpec,
		Resources:                 *getEtcdResource(v),
	}
	etcdCluster.Spec.Version = v.Spec.GetEtcdVersion()
	etcdCluster.Spec.TLS = &etcdv1beta2.TLSPolicy{
		Static: &etcdv1beta2.StaticTLS{
			OperatorSecret: etcdName + "-tls",
			Member: &etcdv1beta2.MemberSecret{
				ServerSecret: etcdName + "-tls",
				PeerSecret:   etcdName + "-tls",
			},
		},
	}
	return etcdCluster, nil
}

func serviceForVault(v *vaultv1alpha1.Vault) *corev1.Service {
	ls := labelsForVault(v.Name)
	selectorLs := labelsForVault(v.Name)
	// Label to differentiate per-instance service and global service via label selection
	ls["global_service"] = "true"
	servicePorts, _ := getServicePorts(v)
	servicePorts = append(servicePorts, corev1.ServicePort{Name: "metrics", Port: 9091})
	servicePorts = append(servicePorts, corev1.ServicePort{Name: "statsd", Port: 9125})
	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name,
			Namespace: v.Namespace,
			Labels:    ls,
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType(v),
			Selector: selectorLs,
			Ports:    servicePorts,
		},
	}
	return service
}

func serviceMonitorForVault(v *vaultv1alpha1.Vault) *monitorv1.ServiceMonitor {
	ls := labelsForVault(v.Name)
	serviceMonitor := &monitorv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name,
			Namespace: v.Namespace,
			Labels:    ls,
		},
		Spec: monitorv1.ServiceMonitorSpec{
			JobLabel: v.Name,
			Selector: metav1.LabelSelector{
				MatchLabels: ls,
			},
			NamespaceSelector: monitorv1.NamespaceSelector{
				MatchNames: []string{v.Namespace},
			},
		},
	}

	vaultVersionWithPrometheus := semver.MustParse("1.1.0")
	version, err := v.Spec.GetVersion()
	if err == nil && !version.LessThan(vaultVersionWithPrometheus) {
		serviceMonitor.Spec.Endpoints = []monitorv1.Endpoint{{
			Interval: "30s",
			Port:     "api-port",
			Scheme:   strings.ToLower(string(getVaultURIScheme(v))),
			Params:   map[string][]string{"format": []string{"prometheus"}},
			Path:     "/v1/sys/metrics",
			TLSConfig: &monitorv1.TLSConfig{
				InsecureSkipVerify: true,
			},
			BearerTokenFile: fmt.Sprintf("/etc/prometheus/secrets/%s/vault.token", v.Name),
		}}
	} else {
		serviceMonitor.Spec.Endpoints = []monitorv1.Endpoint{{
			Interval: "30s",
			Port:     "prometheus",
		}}
	}

	return serviceMonitor
}

func getServicePorts(v *vaultv1alpha1.Vault) ([]corev1.ServicePort, []corev1.ContainerPort) {
	var servicePorts []corev1.ServicePort
	var containerPorts []corev1.ContainerPort

	if len(v.Spec.ServicePorts) == 0 {
		return []corev1.ServicePort{
				{
					Name: "api-port",
					Port: 8200,
				},
				{
					Name: "cluster-port",
					Port: 8201,
				},
			}, []corev1.ContainerPort{
				{
					Name:          "api-port",
					ContainerPort: 8200,
				},
				{
					Name:          "cluster-port",
					ContainerPort: 8201,
				},
			}
	}

	for k, i := range v.Spec.ServicePorts {
		servicePort := corev1.ServicePort{
			Name: k,
			Port: i,
		}
		servicePorts = append(servicePorts, servicePort)

		containerPort := corev1.ContainerPort{
			ContainerPort: i,
			Name:          k,
		}
		containerPorts = append(containerPorts, containerPort)
	}

	sort.Slice(servicePorts, func(i, j int) bool { return servicePorts[i].Name < servicePorts[j].Name })
	sort.Slice(containerPorts, func(i, j int) bool { return containerPorts[i].Name < containerPorts[j].Name })

	return servicePorts, containerPorts
}

func perInstanceServicesForVault(v *vaultv1alpha1.Vault) []*corev1.Service {
	var services []*corev1.Service
	servicePorts, _ := getServicePorts(v)
	servicePorts = append(servicePorts, corev1.ServicePort{Name: "metrics", Port: 9091})

	for i := 0; i < int(v.Spec.Size); i++ {

		podName := fmt.Sprintf("%s-%d", v.Name, i)

		ls := labelsForVault(v.Name)
		ls[appsv1.StatefulSetPodNameLabel] = podName

		service := &corev1.Service{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Service",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: v.Namespace,
				Labels:    ls,
			},
			Spec: corev1.ServiceSpec{
				Type:     serviceType(v),
				Selector: ls,
				Ports:    servicePorts,
			},
		}

		services = append(services, service)
	}

	return services
}

func serviceForVaultConfigurer(v *vaultv1alpha1.Vault) *corev1.Service {
	var servicePorts []corev1.ServicePort

	ls := labelsForVaultConfigurer(v.Name)
	servicePorts = append(servicePorts, corev1.ServicePort{Name: "metrics", Port: 9091})

	serviceName := fmt.Sprintf("%s-configurer", v.Name)

	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: v.Namespace,
			Labels:    ls,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: ls,
			Ports:    servicePorts,
		},
	}
	return service
}

func ingressForVault(v *vaultv1alpha1.Vault) *v1beta1.Ingress {
	if ingress := v.GetIngress(); ingress != nil {
		return &v1beta1.Ingress{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1beta1",
				Kind:       "Ingress",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:        v.Name,
				Namespace:   v.Namespace,
				Annotations: ingress.Annotations,
			},
			Spec: ingress.Spec,
		}
	}
	return nil
}

func serviceType(v *vaultv1alpha1.Vault) corev1.ServiceType {
	switch v.Spec.ServiceType {
	case string(corev1.ServiceTypeClusterIP):
		return corev1.ServiceTypeClusterIP
	case string(corev1.ServiceTypeNodePort):
		return corev1.ServiceTypeNodePort
	case string(corev1.ServiceTypeLoadBalancer):
		return corev1.ServiceTypeLoadBalancer
	case string(corev1.ServiceTypeExternalName):
		return corev1.ServiceTypeExternalName
	default:
		return corev1.ServiceTypeClusterIP
	}
}

func deploymentForConfigurer(v *vaultv1alpha1.Vault, configmaps corev1.ConfigMapList, secrets corev1.SecretList) *appsv1.Deployment {
	ls := labelsForVaultConfigurer(v.Name)

	volumes := []corev1.Volume{}
	volumeMounts := []corev1.VolumeMount{}
	configArgs := []string{}

	sort.Slice(configmaps.Items, func(i, j int) bool { return configmaps.Items[i].Name < configmaps.Items[j].Name })
	sort.Slice(secrets.Items, func(i, j int) bool { return secrets.Items[i].Name < secrets.Items[j].Name })

	for _, cm := range configmaps.Items {
		if _, ok := cm.Data[vault.DefaultConfigFile]; ok {
			volumes = append(volumes, corev1.Volume{
				Name: cm.Name,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: cm.Name},
					},
				},
			})

			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      cm.Name,
				MountPath: "/config/" + cm.Name,
			})

			configArgs = append(configArgs, "--vault-config-file", "/config/"+cm.Name+"/"+vault.DefaultConfigFile)
		}
	}

	for _, secret := range secrets.Items {
		if _, ok := secret.Data[vault.DefaultConfigFile]; ok {
			volumes = append(volumes, corev1.Volume{
				Name: secret.Name,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secret.Name,
					},
				},
			})

			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      secret.Name,
				MountPath: "/config/" + secret.Name,
			})

			configArgs = append(configArgs, "--vault-config-file", "/config/"+secret.Name+"/"+vault.DefaultConfigFile)
		}
	}

	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name + "-configurer",
			Namespace: v.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      ls,
					Annotations: v.Spec.GetAnnotations("9091"),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: v.Spec.GetServiceAccount(),
					Containers: []corev1.Container{
						{
							Image:           v.Spec.GetBankVaultsImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "bank-vaults",
							Command:         []string{"bank-vaults", "configure"},
							Args:            append(v.Spec.UnsealConfig.ToArgs(v), configArgs...),
							Ports: []corev1.ContainerPort{{
								Name:          "metrics",
								ContainerPort: 9091,
								Protocol:      "TCP",
							}},
							Env:          withSecretEnv(v, withTLSEnv(v, false, withCredentialsEnv(v, []corev1.EnvVar{}))),
							VolumeMounts: withTLSVolumeMount(v, withCredentialsVolumeMount(v, volumeMounts)),
							WorkingDir:   "/config",
							Resources:    *getBankVaultsResource(v),
						},
					},
					Volumes:         withTLSVolume(v, withCredentialsVolume(v, volumes)),
					SecurityContext: withSecurityContext(v),
					NodeSelector:    v.Spec.NodeSelector,
					Tolerations:     v.Spec.Tolerations,
				},
			},
		},
	}
	return dep
}

func configMapForConfigurer(v *vaultv1alpha1.Vault) *corev1.ConfigMap {
	ls := labelsForVaultConfigurer(v.Name)
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name + "-configurer",
			Namespace: v.Namespace,
			Labels:    ls,
		},
		Data: map[string]string{vault.DefaultConfigFile: v.Spec.ExternalConfigJSON()},
	}
	return cm
}

func secretForVault(om *vaultv1alpha1.Vault) (*corev1.Secret, error) {
	hostsAndIPs := om.Name + "." + om.Namespace + ",127.0.0.1"
	chain, err := bvtls.GenerateTLS(hostsAndIPs, "8760h")
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
	}
	secret.Name = om.Name + "-tls"
	secret.Namespace = om.Namespace
	secret.Labels = labelsForVault(om.Name)
	secret.StringData = map[string]string{}
	secret.StringData["ca.crt"] = chain.CACert
	secret.StringData["server.crt"] = chain.ServerCert
	secret.StringData["server.key"] = chain.ServerKey
	return secret, nil
}

// statefulSetForVault returns a Vault StatefulSet object
func statefulSetForVault(v *vaultv1alpha1.Vault) (*appsv1.StatefulSet, error) {
	ls := labelsForVault(v.Name)
	replicas := v.Spec.Size

	// validate configuration
	if replicas > 1 && !v.Spec.HasHAStorage() {
		return nil, fmt.Errorf("more than 1 replicas are not supported without HA storage backend")
	}

	volumes := withTLSVolume(v, withCredentialsVolume(v, []corev1.Volume{
		{
			Name: "vault-config",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "vault-file",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}))

	volumes = withStatsdVolume(v, withAuditLogVolume(v, volumes))

	volumeMounts := withTLSVolumeMount(v, withCredentialsVolumeMount(v, []corev1.VolumeMount{
		{
			Name:      "vault-config",
			MountPath: "/vault/config",
		}, {
			Name:      "vault-file",
			MountPath: "/vault/file",
		},
	}))

	volumeMounts = withAuditLogVolumeMount(v, volumeMounts)

	// TODO Configure Vault to wait for etcd in an init container in this case
	// If etcd size is < 0 means not create new etcd cluster
	// No need to override etcd config, and use user input value
	if v.Spec.GetStorageType() == "etcd" && v.Spec.GetEtcdSize() > 0 {

		// Overwrite Vault config with the generated TLS certificate's settings
		etcdStorage := v.Spec.GetStorage()
		etcdStorage["tls_ca_file"] = "/etcd/tls/" + etcdutil.CliCAFile
		etcdStorage["tls_cert_file"] = "/etcd/tls/" + etcdutil.CliCertFile
		etcdStorage["tls_key_file"] = "/etcd/tls/" + etcdutil.CliKeyFile

		// Mount the Secret holding the certificate into Vault
		etcdAddress := etcdStorage["address"].(string)
		etcdURL, err := url.Parse(etcdAddress)
		if err != nil {
			return nil, err
		}
		etcdName := etcdURL.Hostname()

		etcdVolume := corev1.Volume{
			Name: "etcd-tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: etcdName + "-tls",
				},
			},
		}

		volumes = append(volumes, etcdVolume)

		etcdVolumeMount := corev1.VolumeMount{
			Name:      "etcd-tls",
			MountPath: "/etcd/tls",
		}
		volumeMounts = append(volumeMounts, etcdVolumeMount)
	}

	configJSON := v.Spec.ConfigJSON()
	owner := asOwner(v)
	ownerJSON, err := json.Marshal(owner)
	if err != nil {
		return nil, err
	}

	unsealCommand := []string{"bank-vaults", "unseal", "--init"}
	if v.Spec.IsAutoUnseal() {
		unsealCommand = append(unsealCommand, "--auto")
	}
	_, containerPorts := getServicePorts(v)

	dep := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name,
			Namespace: v.Namespace,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
			},
			PodManagementPolicy: appsv1.ParallelPodManagement,
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      ls,
					Annotations: v.Spec.GetAnnotations("9102"),
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						PodAntiAffinity: getPodAntiAffinity(v),
						NodeAffinity:    getNodeAffinity(v),
					},
					ServiceAccountName: v.Spec.GetServiceAccount(),
					Containers: withStatsdContainer(v, string(ownerJSON), withAuditLogContainer(v, string(ownerJSON), []corev1.Container{
						{
							Image:           v.Spec.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "vault",
							Args:            []string{"server"},
							Ports:           containerPorts,
							Env: withTLSEnv(v, true, withCredentialsEnv(v, withVaultEnv(v, []corev1.EnvVar{
								{
									Name:  "VAULT_LOCAL_CONFIG",
									Value: configJSON,
								},
								// https://github.com/hashicorp/docker-vault/blob/master/0.X/docker-entrypoint.sh#L12
								{
									Name:  "VAULT_CLUSTER_INTERFACE",
									Value: "eth0",
								},
							}))),
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"IPC_LOCK"},
								},
							},
							// This probe makes sure Vault is responsive in a HTTPS manner
							// See: https://www.vaultproject.io/api/system/init.html
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Scheme: getVaultURIScheme(v),
										Port:   intstr.FromString("api-port"),
										Path:   "/v1/sys/init",
									}},
							},
							// This probe makes sure that only the active Vault instance gets traffic
							// See: https://www.vaultproject.io/api/system/health.html
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Scheme: getVaultURIScheme(v),
										Port:   intstr.FromString("api-port"),
										Path:   "/v1/sys/health?standbyok&perfstandbyok",
									}},
								PeriodSeconds:    5,
								FailureThreshold: 2,
							},
							VolumeMounts: withVaultVolumeMounts(v, volumeMounts),
							Resources:    *getVaultResource(v),
						},
						{
							Image:           v.Spec.GetBankVaultsImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "bank-vaults",
							Command:         unsealCommand,
							Args:            append(v.Spec.UnsealConfig.Options.ToArgs(), v.Spec.UnsealConfig.ToArgs(v)...),
							Env: withSecretEnv(v, withTLSEnv(v, true, withCredentialsEnv(v, []corev1.EnvVar{
								{
									Name:  k8s.EnvK8SOwnerReference,
									Value: string(ownerJSON),
								},
							}))),
							Ports: []corev1.ContainerPort{{
								Name:          "metrics",
								ContainerPort: 9091,
								Protocol:      "TCP",
							}},
							VolumeMounts: withTLSVolumeMount(v, withCredentialsVolumeMount(v, []corev1.VolumeMount{})),
							Resources:    *getBankVaultsResource(v),
						},
					})),
					Volumes:         withVaultVolumes(v, volumes),
					SecurityContext: withSecurityContext(v),
					NodeSelector:    v.Spec.NodeSelector,
					Tolerations:     v.Spec.Tolerations,
				},
			},
		},
	}
	return dep, nil
}

func withTLSEnv(v *vaultv1alpha1.Vault, localhost bool, envs []corev1.EnvVar) []corev1.EnvVar {
	host := fmt.Sprintf("%s.%s", v.Name, v.Namespace)
	if localhost {
		host = "127.0.0.1"
	}
	if !v.Spec.GetTLSDisable() {
		envs = append(envs, []corev1.EnvVar{
			{
				Name:  api.EnvVaultAddress,
				Value: fmt.Sprintf("https://%s:8200", host),
			},
			{
				Name:  api.EnvVaultCACert,
				Value: "/vault/tls/ca.crt",
			},
		}...)
	} else {
		envs = append(envs, corev1.EnvVar{

			Name:  api.EnvVaultAddress,
			Value: fmt.Sprintf("http://%s:8200", host),
		})
	}
	return envs
}

func withTLSVolume(v *vaultv1alpha1.Vault, volumes []corev1.Volume) []corev1.Volume {
	if !v.Spec.GetTLSDisable() {
		volumes = append(volumes, corev1.Volume{
			Name: "vault-tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: v.Name + "-tls",
				},
			},
		})
	}
	return volumes
}

func withTLSVolumeMount(v *vaultv1alpha1.Vault, volumeMounts []corev1.VolumeMount) []corev1.VolumeMount {
	if !v.Spec.GetTLSDisable() {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "vault-tls",
			MountPath: "/vault/tls",
		})
	}
	return volumeMounts
}

func configMapForStatsD(v *vaultv1alpha1.Vault) *corev1.ConfigMap {
	ls := labelsForVault(v.Name)
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name + "-statsd-mapping",
			Namespace: v.Namespace,
			Labels:    ls,
		},
		Data: map[string]string{"statsd-mapping.conf": `mappings:
    - match: vault.route.*.*
      name: "vault_route"
      labels:
        method: "$1"
        path: "$2"`},
	}
	return cm
}

func configMapForFluentD(v *vaultv1alpha1.Vault) *corev1.ConfigMap {
	ls := labelsForVault(v.Name)
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name + "-fluentd-config",
			Namespace: v.Namespace,
			Labels:    ls,
		},
		Data: map[string]string{"fluent.conf": v.Spec.FluentDConfig},
	}
	return cm
}

func withCredentialsEnv(v *vaultv1alpha1.Vault, envs []corev1.EnvVar) []corev1.EnvVar {
	env := v.Spec.CredentialsConfig.Env
	path := v.Spec.CredentialsConfig.Path
	if env != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  env,
			Value: path,
		})
	}
	return envs
}

func withCredentialsVolume(v *vaultv1alpha1.Vault, volumes []corev1.Volume) []corev1.Volume {
	secretName := v.Spec.CredentialsConfig.SecretName
	if secretName != "" {
		volumes = append(volumes, corev1.Volume{
			Name: secretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: secretName,
				},
			},
		})
	}
	return volumes
}

func withCredentialsVolumeMount(v *vaultv1alpha1.Vault, volumeMounts []corev1.VolumeMount) []corev1.VolumeMount {
	secretName := v.Spec.CredentialsConfig.SecretName
	path := v.Spec.CredentialsConfig.Path
	if secretName != "" {
		_, file := filepath.Split(path)
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      secretName,
			MountPath: path,
			SubPath:   file,
		})
	}
	return volumeMounts
}

func withStatsdVolume(v *vaultv1alpha1.Vault, volumes []corev1.Volume) []corev1.Volume {
	if !v.Spec.IsStatsdDisabled() {
		volumes = append(volumes, []corev1.Volume{
			{
				Name: "statsd-mapping",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: v.Name + "-statsd-mapping"},
					},
				},
			},
		}...)
	}
	return volumes
}

func withStatsdContainer(v *vaultv1alpha1.Vault, owner string, containers []corev1.Container) []corev1.Container {
	if !v.Spec.IsStatsdDisabled() {
		containers = append(containers, corev1.Container{
			Image:           v.Spec.GetStatsDImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Name:            "prometheus-exporter",
			Args:            []string{"--statsd.mapping-config=/tmp/statsd-mapping.conf"},
			Env: withTLSEnv(v, true, withCredentialsEnv(v, []corev1.EnvVar{
				{
					Name:  k8s.EnvK8SOwnerReference,
					Value: owner,
				},
			})),
			Ports: []corev1.ContainerPort{{
				Name:          "statsd",
				ContainerPort: 9125,
				Protocol:      "UDP",
			}, {
				Name:          "prometheus",
				ContainerPort: 9102,
				Protocol:      "TCP",
			}},
			VolumeMounts: []corev1.VolumeMount{{
				Name:      "statsd-mapping",
				MountPath: "/tmp/",
			}},
			Resources: *getPrometheusExporterResource(v),
		})
	}
	return containers
}

func withAuditLogVolume(v *vaultv1alpha1.Vault, volumes []corev1.Volume) []corev1.Volume {
	if v.Spec.IsFluentDEnabled() {
		volumes = append(volumes, []corev1.Volume{
			{
				Name: "vault-auditlogs",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
			{
				Name: "fluentd-config",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: v.Name + "-fluentd-config",
						},
					},
				},
			},
		}...)
	}
	return volumes
}

func withAuditLogVolumeMount(v *vaultv1alpha1.Vault, volumeMounts []corev1.VolumeMount) []corev1.VolumeMount {
	if v.Spec.IsFluentDEnabled() {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "vault-auditlogs",
			MountPath: "/vault/logs",
		})
	}
	return volumeMounts
}

func withAuditLogContainer(v *vaultv1alpha1.Vault, owner string, containers []corev1.Container) []corev1.Container {
	if v.Spec.IsFluentDEnabled() {
		containers = append(containers, corev1.Container{
			Image:           v.Spec.GetFluentDImage(),
			ImagePullPolicy: corev1.PullAlways,
			Name:            "auditlog-exporter",
			Env: withSecretEnv(v, withCredentialsEnv(v, []corev1.EnvVar{
				{
					Name:  k8s.EnvK8SOwnerReference,
					Value: owner,
				},
			})),
			VolumeMounts: withCredentialsVolumeMount(v, []corev1.VolumeMount{
				{
					Name:      "vault-auditlogs",
					MountPath: "/vault/logs",
				},
				{
					Name:      "fluentd-config",
					MountPath: "/fluentd/etc",
				},
			}),
		})
	}
	return containers
}

func getPodAntiAffinity(v *vaultv1alpha1.Vault) *corev1.PodAntiAffinity {
	if v.Spec.PodAntiAffinity == "" {
		return nil
	}

	ls := labelsForVault(v.Name)
	return &corev1.PodAntiAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
			{
				LabelSelector: &metav1.LabelSelector{
					MatchLabels: ls,
				},
				TopologyKey: v.Spec.PodAntiAffinity,
			},
		},
	}
}

func getNodeAffinity(v *vaultv1alpha1.Vault) *corev1.NodeAffinity {
	if v.Spec.NodeAffinity.Size() == 0 {
		return nil
	}
	return &v.Spec.NodeAffinity
}

func getVaultURIScheme(v *vaultv1alpha1.Vault) corev1.URIScheme {
	if v.Spec.GetTLSDisable() {
		return corev1.URISchemeHTTP
	}
	return corev1.URISchemeHTTPS
}

func withVaultVolumes(v *vaultv1alpha1.Vault, volumes []corev1.Volume) []corev1.Volume {
	index := map[string]corev1.Volume{}
	for _, v := range append(volumes, v.Spec.Volumes...) {
		index[v.Name] = v
	}

	volumes = []corev1.Volume{}
	for _, v := range index {
		volumes = append(volumes, v)
	}

	sort.Slice(volumes, func(i, j int) bool { return volumes[i].Name < volumes[j].Name })
	return volumes
}

func withVaultVolumeMounts(v *vaultv1alpha1.Vault, volumeMounts []corev1.VolumeMount) []corev1.VolumeMount {
	index := map[string]corev1.VolumeMount{}
	for _, v := range append(volumeMounts, v.Spec.VolumeMounts...) {
		index[v.Name] = v
	}

	volumeMounts = []corev1.VolumeMount{}
	for _, v := range index {
		volumeMounts = append(volumeMounts, v)
	}

	sort.Slice(volumeMounts, func(i, j int) bool { return volumeMounts[i].Name < volumeMounts[j].Name })
	return volumeMounts
}

func withVaultEnv(v *vaultv1alpha1.Vault, envs []corev1.EnvVar) []corev1.EnvVar {
	for _, env := range v.Spec.VaultEnvsConfig {
		envs = append(envs, env)
	}

	return envs
}

func withSecretEnv(v *vaultv1alpha1.Vault, envs []corev1.EnvVar) []corev1.EnvVar {
	for _, env := range v.Spec.EnvsConfig {
		envs = append(envs, env)
	}

	return envs
}

func withSecurityContext(v *vaultv1alpha1.Vault) *corev1.PodSecurityContext {
	if v.Spec.SecurityContext.Size() == 0 {
		return nil
	}
	return &v.Spec.SecurityContext
}

// labelsForVault returns the labels for selecting the resources
// belonging to the given vault CR name.
func labelsForVault(name string) map[string]string {
	return map[string]string{"app": "vault", "vault_cr": name}
}

// labelsForVaultConfigurer returns the labels for selecting the resources
// belonging to the given vault CR name.
func labelsForVaultConfigurer(name string) map[string]string {
	return map[string]string{"app": "vault-configurator", "vault_cr": name}
}

// asOwner returns an OwnerReference set as the vault CR
func asOwner(v *vaultv1alpha1.Vault) metav1.OwnerReference {
	trueVar := true
	return metav1.OwnerReference{
		APIVersion: v.APIVersion,
		Kind:       v.Kind,
		Name:       v.Name,
		UID:        v.UID,
		Controller: &trueVar,
	}
}

// podList returns a v1.PodList object
func podList() *corev1.PodList {
	return &corev1.PodList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
	}
}

// getPodNames returns the pod names of the array of pods passed in
func getPodNames(pods []corev1.Pod) []string {
	var podNames []string
	for _, pod := range pods {
		podNames = append(podNames, pod.Name)
	}
	return podNames
}

// getVaultResource return resource in spec or return pre-defined resource if not configurated
func getVaultResource(v *vaultv1alpha1.Vault) *corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.Vault != nil {
		return v.Spec.Resources.Vault
	}

	return &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("250m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}

// getBankVaultsResource return resource in spec or return pre-defined resource if not configurated
func getBankVaultsResource(v *vaultv1alpha1.Vault) *corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.BankVaults != nil {
		return v.Spec.Resources.BankVaults
	}

	return &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("200m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
	}
}

// getEtcdResource return resource in spec or return pre-defined resource if not configurated
func getEtcdResource(v *vaultv1alpha1.Vault) *corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.Etcd != nil {
		return v.Spec.Resources.Etcd
	}

	return &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("200m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
	}
}

// getPrometheusExporterResource return resource in spec or return pre-defined resource if not configurated
func getPrometheusExporterResource(v *vaultv1alpha1.Vault) *corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.PrometheusExporter != nil {
		return v.Spec.Resources.PrometheusExporter
	}

	return &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("200m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
	}
}
