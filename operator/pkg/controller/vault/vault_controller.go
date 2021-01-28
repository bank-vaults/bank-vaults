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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/banzaicloud/k8s-objectmatcher/patch"
	etcdv1beta2 "github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	"github.com/coreos/etcd-operator/pkg/util/etcdutil"
	"github.com/hashicorp/vault/api"
	"github.com/imdario/mergo"
	monitorv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/spf13/cast"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	internalVault "github.com/banzaicloud/bank-vaults/internal/vault"
	vaultv1alpha1 "github.com/banzaicloud/bank-vaults/operator/pkg/apis/vault/v1alpha1"
	bvtls "github.com/banzaicloud/bank-vaults/pkg/sdk/tls"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

var log = logf.Log.WithName("controller_vault")

var configFileNames = []string{"vault-config.yml", "vault-config.yaml"}

// Add creates a new Vault Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	reconciler, err := newReconciler(mgr)
	if err != nil {
		return err
	}
	return add(mgr, reconciler)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) (reconcile.Reconciler, error) {
	nonNamespacedClient, err := client.New(mgr.GetConfig(), client.Options{})
	if err != nil {
		return nil, err
	}
	return &ReconcileVault{
		client:              mgr.GetClient(),
		nonNamespacedClient: nonNamespacedClient,
		scheme:              mgr.GetScheme(),
		httpClient:          newHTTPClient(),
	}, nil
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
	client client.Client
	// since the cache inside the client is namespaced we need to create another client which is not namespaced
	// TODO the cache should be restricted to Secrets only right now in this one if possible
	nonNamespacedClient client.Client
	scheme              *runtime.Scheme
	httpClient          *http.Client
}

func (r *ReconcileVault) createOrUpdateObject(o runtime.Object) error {
	return createOrUpdateObjectWithClient(r.client, o)
}

func createOrUpdateObjectWithClient(c client.Client, o runtime.Object) error {
	key, err := client.ObjectKeyFromObject(o)
	if err != nil {
		return err
	}

	current := o.DeepCopyObject()

	err = c.Get(context.TODO(), key, current)
	if apierrors.IsNotFound(err) {
		err := patch.DefaultAnnotator.SetLastAppliedAnnotation(o)
		if err != nil {
			log.Error(err, "failed to annotate original object", "object", o)
		}
		return c.Create(context.TODO(), o)
	} else if err == nil {
		// Handle special cases for update
		switch o.(type) {
		case *corev1.Service:
			currentSvc := current.(*corev1.Service)
			svc := o.(*corev1.Service)
			// Preserve the ClusterIP when updating the service
			svc.Spec.ClusterIP = currentSvc.Spec.ClusterIP
			// Preserve the annotation when updating the service, ensure any updated annotation is preserved
			for key, value := range currentSvc.Annotations {
				if _, present := svc.Annotations[key]; !present {
					svc.Annotations[key] = value
				}
			}

			if svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
				for i := range svc.Spec.Ports {
					svc.Spec.Ports[i].NodePort = currentSvc.Spec.Ports[i].NodePort
				}
			}
		}

		result, err := patch.DefaultPatchMaker.Calculate(current, o, patch.IgnoreStatusFields())
		if err != nil {
			log.Error(err, "failed to calculate patch to match objects, moving on to update")
			// if there is an error with matching, we still want to update
			resourceVersion := current.(metav1.ObjectMetaAccessor).GetObjectMeta().GetResourceVersion()
			o.(metav1.ObjectMetaAccessor).GetObjectMeta().SetResourceVersion(resourceVersion)

			return c.Update(context.TODO(), o)
		}

		if !result.IsEmpty() {
			log.V(1).Info(fmt.Sprintf("Resource update for object %s:%s", o.GetObjectKind(), o.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()),
				"patch", string(result.Patch),
				// "original", string(result.Original),
				// "modified", string(result.Modified),
				// "current", string(result.Current),
			)

			err := patch.DefaultAnnotator.SetLastAppliedAnnotation(o)
			if err != nil {
				log.Error(err, "failed to annotate modified object", "object", o)
			}

			resourceVersion := current.(metav1.ObjectMetaAccessor).GetObjectMeta().GetResourceVersion()
			o.(metav1.ObjectMetaAccessor).GetObjectMeta().SetResourceVersion(resourceVersion)

			return c.Update(context.TODO(), o)
		}

		log.V(1).Info(fmt.Sprintf("Skipping update for object %s:%s", o.GetObjectKind(), o.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()))
	}

	return err
}

// Check if secret match the labels or annotations selectors
// If any of the Labels selector OR Annotation Selector match it will return true
func secretMatchLabelsOrAnnotations(s corev1.Secret, labelsSelectors []map[string]string, annotationsSelectors []map[string]string) bool {

	sm := s.ObjectMeta
	log.V(1).Info(fmt.Sprintf("External Secrets Watcher: Checking labels and annotations for secret:  %s/%s", sm.GetNamespace(), sm.GetName()))

	// Secret Labels
	ol := sm.GetLabels()
	// Iterate over labels selectors []map[string]string
	for _, l := range labelsSelectors {
		log.V(1).Info(fmt.Sprintf("External Secrets Watcher: Checking for labels selector: %v", l))
		if labels.SelectorFromSet(l).Matches(labels.Set(ol)) {
			log.V(1).Info(fmt.Sprintf("External Secrets Watcher: Secret %s/%s matched label selector: %v", sm.GetNamespace(), sm.GetName(), l))
			log.V(1).Info(fmt.Sprintf("External Secrets Watcher: adding Secret %s/%s to watch list", sm.GetNamespace(), sm.GetName()))
			return true
		}
	}

	// Secret Annotations
	oa := sm.GetAnnotations()
	// Iterate over annotations selectors []map[string]string
	for _, a := range annotationsSelectors {
		log.V(1).Info(fmt.Sprintf("External Secrets Watcher: Checking for annotation selector: %v", a))
		if labels.SelectorFromSet(a).Matches(labels.Set(oa)) {
			log.V(1).Info(fmt.Sprintf("External Secrets Watcher: Secret %s/%s matched annotation selector: %v", sm.GetNamespace(), sm.GetName(), a))
			log.V(1).Info(fmt.Sprintf("External Secrets Watcher: adding Secret %s/%s to watch list", sm.GetNamespace(), sm.GetName()))
			return true
		}
	}

	return false
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
		if apierrors.IsNotFound(err) {
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
	if v.Spec.HasEtcdStorage() && v.Spec.GetEtcdSize() > 0 {
		etcdCluster, err := etcdForVault(v)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to fabricate etcd cluster: %v", err)
		}

		// Create the secret if it doesn't exist
		sec, err := secretForEtcd(v, etcdCluster)
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

	// Create the service if it doesn't exist
	service := serviceForVault(v)
	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, service, r.scheme); err != nil {
		return reconcile.Result{}, err
	}
	err = r.createOrUpdateObject(service)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to create/update service: %v", err)
	}

	// If we are using a LoadBalancer let the cloud-provider code fill in the hostname or IP of it,
	// so we have a more stable certificate generation process.
	if service.Spec.Type == corev1.ServiceTypeLoadBalancer && !v.Spec.IsTLSDisabled() && v.Spec.ExistingTLSSecretName == "" {
		key, err := client.ObjectKeyFromObject(service)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to get object key for service: %v", err)
		}

		err = r.client.Get(context.Background(), key, service)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to get Vault LB service: %v", err)
		}

		if len(loadBalancerIngressPoints(service)) == 0 {
			reqLogger.Info("The Vault LB Service has no Ingress points yet, waiting 5 seconds...")
			return reconcile.Result{Requeue: true, RequeueAfter: 5 * time.Second}, nil
		}
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

	tlsExpiration := time.Time{}
	if !v.Spec.IsTLSDisabled() {
		// Check if we have an existing TLS Secret for Vault
		secretName := v.Name + "-tls"
		if v.Spec.ExistingTLSSecretName != "" {
			secretName = v.Spec.ExistingTLSSecretName
		}
		sec := &corev1.Secret{}
		// Get tls secret
		err := r.client.Get(context.TODO(), types.NamespacedName{
			Namespace: v.Namespace,
			Name:      secretName,
		}, sec)
		if apierrors.IsNotFound(err) && v.Spec.ExistingTLSSecretName == "" {
			// If tls secret doesn't exist generate tls
			tlsExpiration, err = populateTLSSecret(v, service, sec)
			if err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to fabricate secret for vault: %v", err)
			}
		} else if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to get tls secret for vault: %v", err)
		} else if v.Spec.ExistingTLSSecretName == "" && len(sec.Data) > 0 {
			// If tls secret exists check expiration date and if hosts have changed
			certificate, err := bvtls.PEMToCertificate(sec.Data["server.crt"])
			if err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to get certificate from secret: %v", err)
			}

			tlsExpiration = certificate.NotAfter
			tlsHostsChanged := certHostsAndIPsChanged(v, service, certificate)

			// Do we need to regenerate the TLS certificate and possibly even the CA?
			if time.Until(tlsExpiration) < v.Spec.GetTLSExpiryThreshold() {
				// Generate new TLS server certificate if expiration date is too close
				reqLogger.Info("cert expiration date too close", "date", tlsExpiration.UTC().Format(time.RFC3339))
				tlsExpiration, err = populateTLSSecret(v, service, sec)
			} else if tlsHostsChanged {
				// Generate new TLS server certificate if the TLS hosts have changed
				reqLogger.Info("TLS server hosts have changed")
				tlsExpiration, err = populateTLSSecret(v, service, sec)
			}
			if err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to fabricate secret for vault: %v", err)
			}
		}

		// Set Vault instance as the owner and controller
		if v.Spec.ExistingTLSSecretName == "" {
			if err := controllerutil.SetControllerReference(v, sec, r.scheme); err != nil {
				return reconcile.Result{}, err
			}
			err = r.createOrUpdateObject(sec)
			if err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to create secret for vault: %v", err)
			}
		}

		// Distribute the CA certificate to every namespace defined
		if len(v.Spec.CANamespaces) > 0 {
			err = r.distributeCACertificate(v, client.ObjectKey{Name: sec.Name, Namespace: sec.Namespace})
			if err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to distribute CA secret for vault: %v", err)
			}
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

	if !v.Spec.IsStatsDDisabled() {
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

	// Manage annotation for external secrets to watch and trigger restart of StatefulSet
	externalSecretsToWatchLabelsSelector := v.Spec.GetWatchedSecretsLabels()
	externalSecretsToWatchAnnotationsSelector := v.Spec.GetWatchedSecretsAnnotations()
	externalSecretsToWatchItems := []corev1.Secret{}

	if len(externalSecretsToWatchLabelsSelector) != 0 || len(externalSecretsToWatchAnnotationsSelector) != 0 {

		externalSecretsInNamespace := corev1.SecretList{}
		// Get all Secrets for the Vault CRD Namespace
		externalSecretsInNamespaceFilter := client.ListOptions{
			Namespace: v.Namespace,
		}

		if err = r.client.List(context.TODO(), &externalSecretsInNamespace, &externalSecretsInNamespaceFilter); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to list secrets in the CRD namespace: %v", err)
		}

		for _, secret := range externalSecretsInNamespace.Items {
			if secretMatchLabelsOrAnnotations(secret, externalSecretsToWatchLabelsSelector, externalSecretsToWatchAnnotationsSelector) {
				externalSecretsToWatchItems = append(externalSecretsToWatchItems, secret)
			}
		}

	}

	// Create the StatefulSet if it doesn't exist
	tlsAnnotations := map[string]string{}
	tlsAnnotations["vault.banzaicloud.io/tls-expiration-date"] = tlsExpiration.UTC().Format(time.RFC3339)
	statefulSet, err := statefulSetForVault(v, externalSecretsToWatchItems, tlsAnnotations, service)
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

	// Create configurer if there is any external config
	if len(v.Spec.ExternalConfig.Raw) != 0 {
		err := r.deployConfigurer(v, tlsAnnotations)
		if err != nil {
			return reconcile.Result{}, err
		}
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
	labelSelector := labels.SelectorFromSet(v.LabelsForVault())
	listOps := &client.ListOptions{
		LabelSelector: labelSelector,
		Namespace:     v.Namespace,
	}
	err = r.client.List(context.TODO(), podList, listOps)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to list pods: %v", err)
	}
	podNames := getPodNames(podList.Items)

	var leader string
	var statusError string
	for i := 0; i < int(v.Spec.Size); i++ {
		client, err := vault.NewInsecureRawClient()
		if err != nil {
			return reconcile.Result{}, err
		}

		podName := fmt.Sprintf("%s-%d", v.Name, i)
		client.SetAddress(fmt.Sprintf("%s://%s.%s:8200", strings.ToLower(string(getVaultURIScheme(v))), podName, v.Namespace))

		health, err := client.Sys().Health()
		if err != nil {
			statusError = err.Error()
			break
		} else if !health.Standby {
			leader = podName
		}
	}

	// Fetch the Vault instance again to minimize the possibility of updating a stale object
	// see https://github.com/banzaicloud/bank-vaults/issues/364
	v = &vaultv1alpha1.Vault{}
	err = r.client.Get(context.TODO(), request.NamespacedName, v)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	conditionStatus := v1.ConditionFalse
	if leader != "" && statusError == "" {
		conditionStatus = v1.ConditionTrue
	}

	if !reflect.DeepEqual(podNames, v.Status.Nodes) || !reflect.DeepEqual(leader, v.Status.Leader) || len(v.Status.Conditions) == 0 ||
		v.Status.Conditions[0].Status != conditionStatus || v.Status.Conditions[0].Error != statusError {
		v.Status.Nodes = podNames
		v.Status.Leader = leader
		v.Status.Conditions = []v1.ComponentCondition{{
			Type:   v1.ComponentHealthy,
			Status: conditionStatus,
			Error:  statusError,
		}}
		log.V(1).Info("Updating vault status", "status", v.Status, "resourceVersion", v.ResourceVersion)
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

func secretForEtcd(v *vaultv1alpha1.Vault, e *etcdv1beta2.EtcdCluster) (*corev1.Secret, error) {
	hosts := []string{
		e.Name,
		e.Name + "." + e.Namespace,
		e.Name + "." + e.Namespace + ".svc.cluster.local",
		"*." + e.Name + "." + e.Namespace + ".svc",
		"*." + e.Name + "." + e.Namespace + ".svc.cluster.local",
		e.Name + "-client." + e.Namespace + ".svc",
		e.Name + "-client." + e.Namespace + ".svc.cluster.local",
		"localhost",
	}
	cm, err := bvtls.NewCertificateManager(strings.Join(hosts, ","), "8760h")
	if err != nil {
		return nil, err
	}
	err = cm.NewChain()
	if err != nil {
		return nil, err
	}

	secret := corev1.Secret{}
	secret.Name = e.Name + "-tls"
	secret.Namespace = e.Namespace
	secret.Labels = v.LabelsForVault()
	secret.StringData = map[string]string{}

	secret.StringData[etcdutil.CliCAFile] = cm.Chain.CACert
	secret.StringData[etcdutil.CliCertFile] = cm.Chain.ClientCert
	secret.StringData[etcdutil.CliKeyFile] = cm.Chain.ClientKey

	secret.StringData["peer-ca.crt"] = cm.Chain.CACert
	secret.StringData["peer.crt"] = cm.Chain.PeerCert
	secret.StringData["peer.key"] = cm.Chain.PeerKey

	secret.StringData["server-ca.crt"] = cm.Chain.CACert
	secret.StringData["server.crt"] = cm.Chain.ServerCert
	secret.StringData["server.key"] = cm.Chain.ServerKey

	return &secret, nil
}

func etcdForVault(v *vaultv1alpha1.Vault) (*etcdv1beta2.EtcdCluster, error) {
	storage := v.Spec.GetEtcdStorage()
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
	etcdCluster.Labels = v.LabelsForVault()
	etcdCluster.Spec.Size = v.Spec.GetEtcdSize()
	etcdCluster.Spec.Repository = v.Spec.EtcdRepository
	etcdCluster.Spec.Pod = &etcdv1beta2.PodPolicy{
		PersistentVolumeClaimSpec: v.Spec.EtcdPVCSpec,
		Resources:                 getEtcdResource(v),
		Annotations:               v.Spec.EtcdPodAnnotations,
		BusyboxImage:              v.Spec.EtcdPodBusyBoxImage,
		Affinity:                  getEtcdAffinity(v, etcdName),
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
	ls := v.LabelsForVault()
	// label to differentiate per-instance service and global service via label selection
	ls["global_service"] = "true"

	selectorLs := v.LabelsForVault()
	// add the service_registration label
	if v.Spec.ServiceRegistrationEnabled {
		selectorLs["vault-active"] = "true"
	}

	servicePorts, _ := getServicePorts(v)

	annotations := withVaultAnnotations(v, getCommonAnnotations(v, map[string]string{}))

	// On GKE we need to specifiy the backend protocol on the service if TLS is enabled
	if ingress := v.GetIngress(); ingress != nil && !v.Spec.IsTLSDisabled() {
		annotations["cloud.google.com/app-protocols"] = fmt.Sprintf("{\"%s\":\"HTTPS\"}", v.Spec.GetAPIPortName())
	}

	servicePorts = append(servicePorts, corev1.ServicePort{Name: "metrics", Port: 9091})
	servicePorts = append(servicePorts, corev1.ServicePort{Name: "statsd", Port: 9102})
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        v.Name,
			Namespace:   v.Namespace,
			Annotations: annotations,
			Labels:      withVaultLabels(v, ls),
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType(v),
			Selector: selectorLs,
			Ports:    servicePorts,
			// Optional setting for requesting specific load balancer ip addresses.
			LoadBalancerIP: v.Spec.LoadBalancerIP,
			// In case of multi-cluster deployments we need to publish the port
			// before being considered ready, otherwise the LoadBalancer won't
			// be able to direct traffic from the leader to the joining instance.
			PublishNotReadyAddresses: v.Spec.IsRaftBootstrapFollower(),
		},
	}
	return service
}

func serviceMonitorForVault(v *vaultv1alpha1.Vault) *monitorv1.ServiceMonitor {
	ls := v.LabelsForVault()
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
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      appsv1.StatefulSetPodNameLabel,
						Operator: metav1.LabelSelectorOpExists,
					},
				},
			},
			NamespaceSelector: monitorv1.NamespaceSelector{
				MatchNames: []string{v.Namespace},
			},
		},
	}

	vaultVersionWithPrometheus := semver.MustParse("1.1.0")
	version, err := v.Spec.GetVersion()
	if err == nil && !version.LessThan(vaultVersionWithPrometheus) {
		endpoint := monitorv1.Endpoint{
			Interval: "30s",
			Port:     v.Spec.GetAPIPortName(),
			Scheme:   strings.ToLower(string(getVaultURIScheme(v))),
			Params:   map[string][]string{"format": {"prometheus"}},
			Path:     "/v1/sys/metrics",
			TLSConfig: &monitorv1.TLSConfig{
				SafeTLSConfig: monitorv1.SafeTLSConfig{
					InsecureSkipVerify: true,
				},
			},
		}
		if !v.Spec.IsTelemetryUnauthenticated() {
			endpoint.BearerTokenFile = fmt.Sprintf("/etc/prometheus/config_out/.%s-token", v.Name)
		}
		serviceMonitor.Spec.Endpoints = []monitorv1.Endpoint{endpoint}
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
					Name: v.Spec.GetAPIPortName(),
					Port: 8200,
				},
				{
					Name: "cluster-port",
					Port: 8201,
				},
			}, []corev1.ContainerPort{
				{
					Name:          v.Spec.GetAPIPortName(),
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

func perInstanceVaultServiceName(svc string, i int) string {
	return fmt.Sprintf("%s-%d", svc, i)
}

func perInstanceServicesForVault(v *vaultv1alpha1.Vault) []*corev1.Service {
	var services []*corev1.Service
	servicePorts, _ := getServicePorts(v)
	servicePorts = append(servicePorts, corev1.ServicePort{Name: "metrics", Port: 9091})

	for i := 0; i < int(v.Spec.Size); i++ {

		podName := perInstanceVaultServiceName(v.Name, i)

		ls := v.LabelsForVault()
		ls[appsv1.StatefulSetPodNameLabel] = podName

		service := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        podName,
				Namespace:   v.Namespace,
				Annotations: withVaultAnnotations(v, getCommonAnnotations(v, map[string]string{})),
				Labels:      withVaultLabels(v, ls),
			},
			Spec: corev1.ServiceSpec{
				Type:                     corev1.ServiceTypeClusterIP,
				Selector:                 ls,
				Ports:                    servicePorts,
				PublishNotReadyAddresses: true,
			},
		}

		services = append(services, service)
	}

	return services
}

func serviceForVaultConfigurer(v *vaultv1alpha1.Vault) *corev1.Service {
	var servicePorts []corev1.ServicePort

	ls := v.LabelsForVaultConfigurer()
	servicePorts = append(servicePorts, corev1.ServicePort{Name: "metrics", Port: 9091})

	serviceName := fmt.Sprintf("%s-configurer", v.Name)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        serviceName,
			Namespace:   v.Namespace,
			Annotations: withVaultConfigurerAnnotations(v, map[string]string{}),
			Labels:      withVaultConfigurerLabels(v, ls),
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
			ObjectMeta: metav1.ObjectMeta{
				Name:        v.Name,
				Namespace:   v.Namespace,
				Annotations: ingress.Annotations,
				Labels:      v.LabelsForVault(),
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

func deploymentForConfigurer(v *vaultv1alpha1.Vault, configmaps corev1.ConfigMapList, secrets corev1.SecretList, tlsAnnotations map[string]string) (*appsv1.Deployment, error) {
	ls := v.LabelsForVaultConfigurer()

	volumes := []corev1.Volume{}
	volumeMounts := []corev1.VolumeMount{}
	configArgs := []string{}

	sort.Slice(configmaps.Items, func(i, j int) bool { return configmaps.Items[i].Name < configmaps.Items[j].Name })
	sort.Slice(secrets.Items, func(i, j int) bool { return secrets.Items[i].Name < secrets.Items[j].Name })

	for _, cm := range configmaps.Items {
		for _, fileName := range configFileNames {
			if _, ok := cm.Data[fileName]; ok {
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

				// volumeMounts = withBanksVaultsVolumeMounts(v, volumeMounts)

				configArgs = append(configArgs, "--vault-config-file", "/config/"+cm.Name+"/"+fileName)

				break
			}
		}
	}

	for _, secret := range secrets.Items {
		for _, fileName := range configFileNames {
			if _, ok := secret.Data[fileName]; ok {
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

				configArgs = append(configArgs, "--vault-config-file", "/config/"+secret.Name+"/"+fileName)

				break
			}
		}
	}

	// If Vault runs with PCSCD the configurer needs to run on the same host
	// to be able to access the shared (hostPath) UNIX socket of that daemon.
	var affinity *corev1.Affinity
	if v.Spec.UnsealConfig.HSMDaemonNeeded() {
		affinity = &corev1.Affinity{
			PodAffinity: &corev1.PodAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: v.LabelsForVault(),
						},
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		}
	}

	podSpec := corev1.PodSpec{
		ServiceAccountName:           v.Spec.GetServiceAccount(),
		AutomountServiceAccountToken: pointer.BoolPtr(true),

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
				Env:          withNamespaceEnv(v, withCommonEnv(v, withTLSEnv(v, false, withCredentialsEnv(v, []corev1.EnvVar{})))),
				VolumeMounts: withHSMVolumeMount(v, withTLSVolumeMount(v, withCredentialsVolumeMount(v, volumeMounts))),
				WorkingDir:   "/config",
				Resources:    getBankVaultsResource(v),
			},
		},
		Volumes:         withHSMVolume(v, withTLSVolume(v, withCredentialsVolume(v, volumes))),
		SecurityContext: withPodSecurityContext(v),
		NodeSelector:    v.Spec.NodeSelector,
		Tolerations:     v.Spec.Tolerations,
		Affinity:        affinity,
	}

	// merge provided VaultConfigurerPodSpec into the PodSpec defined above
	// the values in VaultConfigurerPodSpec will never overwrite fields defined in the PodSpec above
	if v.Spec.VaultConfigurerPodSpec != nil {
		if err := mergo.Merge(&podSpec, v1.PodSpec(*v.Spec.VaultConfigurerPodSpec)); err != nil {
			return nil, err
		}
	}

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        v.Name + "-configurer",
			Namespace:   v.Namespace,
			Annotations: withVaultConfigurerAnnotations(v, map[string]string{}),
			Labels:      withVaultConfigurerLabels(v, ls),
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			RevisionHistoryLimit: pointer.Int32Ptr(0),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      withVaultConfigurerLabels(v, ls),
					Annotations: withVaultConfigurerAnnotations(v, withPrometheusAnnotations("9091", tlsAnnotations)),
				},
				Spec: podSpec,
			},
		},
	}
	return dep, nil
}

func configMapForConfigurer(v *vaultv1alpha1.Vault) *corev1.ConfigMap {
	ls := v.LabelsForVaultConfigurer()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name + "-configurer",
			Namespace: v.Namespace,
			Labels:    withVaultConfigurerLabels(v, ls),
		},
		Data: map[string]string{internalVault.DefaultConfigFile: v.Spec.ExternalConfigJSON()},
	}
	return cm
}

func hostsForService(svc, namespace string) []string {
	return []string{
		svc,
		svc + "." + namespace,
		svc + "." + namespace + ".svc.cluster.local",
	}
}

func hostsAndIPsForVault(v *vaultv1alpha1.Vault, service *corev1.Service) []string {
	hostsAndIPs := []string{"127.0.0.1"}

	hostsAndIPs = append(hostsAndIPs, hostsForService(v.Name, v.Namespace)...)
	hostsAndIPs = append(hostsAndIPs, loadBalancerIngressPoints(service)...)

	// Add additional TLS hosts from the Vault Spec
	for _, additionalHost := range v.Spec.TLSAdditionalHosts {
		if additionalHost != "" {
			hostsAndIPs = append(hostsAndIPs, additionalHost)
		}
	}

	if v.Spec.Size > 1 {
		for i := 0; i < int(v.Spec.Size); i++ {
			hostsAndIPs = append(hostsAndIPs,
				hostsForService(perInstanceVaultServiceName(v.Name, i), v.Namespace)...)
		}
	}

	return hostsAndIPs
}

func loadBalancerIngressPoints(service *corev1.Service) []string {
	var hostsAndIPs []string

	// Use defined IP
	if service.Spec.LoadBalancerIP != "" {
		hostsAndIPs = append(hostsAndIPs, service.Spec.LoadBalancerIP)

		// Use allocated IP or Hostname
	} else {
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				hostsAndIPs = append(hostsAndIPs, ingress.IP)
			}
			if ingress.Hostname != "" {
				hostsAndIPs = append(hostsAndIPs, ingress.Hostname)
			}
		}
	}
	return hostsAndIPs
}

// populateTLSSecret will populate a secret containing a TLS chain
func populateTLSSecret(v *vaultv1alpha1.Vault, service *corev1.Service, secret *corev1.Secret) (time.Time, error) {
	hostsAndIPs := hostsAndIPsForVault(v, service)

	certMgr, err := bvtls.NewCertificateManager(strings.Join(hostsAndIPs, ","), "8760h")
	if err != nil {
		return time.Time{}, err
	}

	if secret == nil {
		return time.Time{}, errors.New("a nil secret was passed into populateTLSSecret, please instantiate the secret first")
	}

	// These will be empty if the keys don't exist on the Data map
	caCrt := secret.Data["ca.crt"]
	caKey := secret.Data["ca.key"]

	// Load the existing certificate authority
	// Check that the CA certificate and key are not empty
	// We explicitly do not regenerate the CA if there is an error loading it
	// replacing an existing CA unexpectedly (in case of an error) is likely
	// to be worse than not renewing it
	err = certMgr.LoadCA(caCrt, caKey, v.Spec.GetTLSExpiryThreshold())

	// If the CA is expired, empty or not valid but not errored - create a new chain
	if err == bvtls.ExpiredCAError || err == bvtls.EmptyCAError {
		log.Info("TLS CA will be regenerated due to: ", "error", err.Error())

		err = certMgr.NewChain()
		if err != nil {
			return time.Time{}, err
		}
	} else if err != nil {
		return time.Time{}, err
	}

	// Generate a server certificate
	err = certMgr.GenerateServer()
	if err != nil {
		return time.Time{}, err
	}

	secret.Name = v.Name + "-tls"
	secret.Namespace = v.Namespace
	secret.Labels = withVaultLabels(v, v.LabelsForVault())
	secret.Annotations = withVaultAnnotations(v, getCommonAnnotations(v, map[string]string{}))
	secret.StringData = map[string]string{}
	secret.StringData["ca.crt"] = certMgr.Chain.CACert
	secret.StringData["ca.key"] = certMgr.Chain.CAKey
	secret.StringData["server.crt"] = certMgr.Chain.ServerCert
	secret.StringData["server.key"] = certMgr.Chain.ServerKey

	tlsExpiration, err := bvtls.GetCertExpirationDate([]byte(certMgr.Chain.ServerCert))
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get certificate expiration: %v", err)
	}

	return tlsExpiration, nil
}

// statefulSetForVault returns a Vault StatefulSet object
func statefulSetForVault(v *vaultv1alpha1.Vault, externalSecretsToWatchItems []corev1.Secret, tlsAnnotations map[string]string, service *corev1.Service) (*appsv1.StatefulSet, error) {
	ls := v.LabelsForVault()
	replicas := v.Spec.Size

	// validate configuration
	if replicas > 1 && !v.Spec.HasHAStorage() {
		return nil, fmt.Errorf("more than 1 replicas are not supported without HA storage backend")
	}

	configSizeLimit := resource.MustParse("1Mi")

	volumes := withTLSVolume(v, withCredentialsVolume(v, []corev1.Volume{
		{
			Name: "vault-config",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium:    corev1.StorageMediumMemory,
					SizeLimit: &configSizeLimit,
				},
			},
		},
	}))

	volumes = withHSMVolume(v, withStatsdVolume(v, withAuditLogVolume(v, volumes)))

	volumeMounts := withTLSVolumeMount(v, withCredentialsVolumeMount(v, []corev1.VolumeMount{
		{
			Name:      "vault-config",
			MountPath: "/vault/config",
		},
	}))

	volumeMounts = withAuditLogVolumeMount(v, volumeMounts)

	// TODO Configure Vault to wait for etcd in an init container in this case
	// If etcd size is < 0 means not create new etcd cluster
	// No need to override etcd config, and use user input value
	if v.Spec.HasEtcdStorage() && v.Spec.GetEtcdSize() > 0 {

		// Mount the Secret holding the certificate into Vault
		etcdStorage := v.Spec.GetEtcdStorage()
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

	unsealCommand := []string{"bank-vaults", "unseal", "--init"}

	if v.Spec.IsAutoUnseal() {
		unsealCommand = append(unsealCommand, "--auto")
	}

	if v.Spec.IsRaftStorage() {
		raftLeaderAddress := v.Name
		if v.Spec.IsRaftBootstrapFollower() {
			raftLeaderAddress = v.Spec.RaftLeaderAddress
		}

		unsealCommand = append(unsealCommand, "--raft", "--raft-leader-address", v.Spec.GetAPIScheme()+"://"+raftLeaderAddress+":8200")

		if v.Spec.IsRaftBootstrapFollower() {
			unsealCommand = append(unsealCommand, "--raft-secondary")
		}
	} else if v.Spec.IsRaftHAStorage() {
		unsealCommand = append(unsealCommand, "--raft-ha-storage")
	}

	configJSON, err := v.ConfigJSON()
	if err != nil {
		return nil, err
	}

	_, containerPorts := getServicePorts(v)

	containers := withVeleroContainer(v, withStatsDContainer(v, withAuditLogContainer(v, []corev1.Container{
		{
			Image:           v.Spec.GetVaultImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Name:            "vault",
			Args:            []string{"server"},
			Ports:           containerPorts,
			Env: withClusterAddr(v, service, withCredentialsEnv(v, withVaultEnv(v, []corev1.EnvVar{
				{
					Name: "VAULT_K8S_POD_NAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.name",
						},
					},
				},
			}))),
			SecurityContext: withContainerSecurityContext(v),
			// This probe makes sure Vault is responsive in a HTTPS manner
			// See: https://www.vaultproject.io/api/system/init.html
			LivenessProbe: &corev1.Probe{
				Handler: corev1.Handler{
					HTTPGet: &corev1.HTTPGetAction{
						Scheme: getVaultURIScheme(v),
						Port:   intstr.FromString(v.Spec.GetAPIPortName()),
						Path:   "/v1/sys/init",
					}},
			},
			// This probe makes sure that only the active Vault instance gets traffic
			// See: https://www.vaultproject.io/api/system/health.html
			ReadinessProbe: &corev1.Probe{
				Handler: corev1.Handler{
					HTTPGet: &corev1.HTTPGetAction{
						Scheme: getVaultURIScheme(v),
						Port:   intstr.FromString(v.Spec.GetAPIPortName()),
						Path:   "/v1/sys/health?standbyok=true&perfstandbyok=true&drsecondarycode=299",
					}},
				PeriodSeconds:    5,
				FailureThreshold: 2,
			},
			VolumeMounts: withVaultVolumeMounts(v, volumeMounts),
			Resources:    getVaultResource(v),
		},
		{
			Image:           v.Spec.GetBankVaultsImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Name:            "bank-vaults",
			Command:         unsealCommand,
			Args:            append(v.Spec.UnsealConfig.Options.ToArgs(), v.Spec.UnsealConfig.ToArgs(v)...),
			Env: withSidecarEnv(v, withTLSEnv(v, true, withCredentialsEnv(v, withCommonEnv(v, []corev1.EnvVar{
				{
					Name: "POD_NAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.name",
						},
					},
				},
			})))),
			Ports: []corev1.ContainerPort{{
				Name:          "metrics",
				ContainerPort: 9091,
				Protocol:      "TCP",
			}},
			VolumeMounts: withHSMVolumeMount(v, withBanksVaultsVolumeMounts(v, withTLSVolumeMount(v, withCredentialsVolumeMount(v, []corev1.VolumeMount{})))),
			Resources:    getBankVaultsResource(v),
		},
	})))

	if v.Spec.UnsealConfig.HSMDaemonNeeded() {
		containers = append(containers, corev1.Container{
			Image:           v.Spec.GetBankVaultsImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Name:            "bank-vaults-hsm-pcscd",
			Command:         []string{"pcscd-entrypoint.sh"},
			VolumeMounts:    withHSMVolumeMount(v, nil),
			Resources:       getHSMDaemonResource(v),
			SecurityContext: &corev1.SecurityContext{
				Privileged: pointer.BoolPtr(true),
				RunAsUser:  pointer.Int64Ptr(0),
			},
		})
	}

	affinity := &corev1.Affinity{
		PodAntiAffinity: getPodAntiAffinity(v),
		NodeAffinity:    getNodeAffinity(v),
	}
	if v.Spec.Affinity != nil {
		affinity = v.Spec.Affinity
	}

	podSpec := corev1.PodSpec{
		Affinity: affinity,

		ServiceAccountName:           v.Spec.GetServiceAccount(),
		AutomountServiceAccountToken: pointer.BoolPtr(true),

		InitContainers: withVaultInitContainers(v, []corev1.Container{
			{
				Image:           v.Spec.GetBankVaultsImage(),
				ImagePullPolicy: corev1.PullIfNotPresent,
				Name:            "config-templating",
				Command:         []string{"template", "-file", "/vault/config/vault.json"},
				Env: withCredentialsEnv(v, withVaultEnv(v, []corev1.EnvVar{
					{
						Name:  "VAULT_LOCAL_CONFIG",
						Value: configJSON,
					},
					{
						Name: "POD_NAME",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "metadata.name",
							},
						},
					},
				})),
				VolumeMounts: withVaultVolumeMounts(v, volumeMounts),
				Resources:    getVaultResource(v),
			},
		}),

		Containers:      containers,
		Volumes:         withVaultVolumes(v, volumes),
		SecurityContext: withPodSecurityContext(v),
		NodeSelector:    v.Spec.NodeSelector,
		Tolerations:     v.Spec.Tolerations,
	}

	// merge provided VaultPodSpec into the PodSpec defined above
	// the values in VaultPodSpec will never overwrite fields defined in the PodSpec above
	if v.Spec.VaultPodSpec != nil {
		if err := mergo.Merge(&podSpec, v1.PodSpec(*v.Spec.VaultPodSpec), mergo.WithOverride); err != nil {
			return nil, err
		}
	}

	// merge provided VaultContainerSpec into the Vault Container defined above
	// the values in VaultContainerSpec will never overwrite fields defined in the PodSpec above
	if err := mergo.Merge(&podSpec.Containers[0], v.Spec.VaultContainerSpec, mergo.WithOverride); err != nil {
		return nil, err
	}

	podManagementPolicy := appsv1.ParallelPodManagement
	if v.Spec.IsRaftStorage() || v.Spec.IsRaftHAStorage() {
		podManagementPolicy = appsv1.OrderedReadyPodManagement
	}

	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:        v.Name,
			Namespace:   v.Namespace,
			Annotations: withVaultAnnotations(v, getCommonAnnotations(v, map[string]string{})),
			Labels:      withVaultLabels(v, ls),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
			},
			PodManagementPolicy: podManagementPolicy,
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: withVaultLabels(v, ls),
					Annotations: withVeleroAnnotations(v,
						withTLSExpirationAnnotations(tlsAnnotations,
							withVaultAnnotations(v,
								withVaultWatchedExternalSecrets(v, externalSecretsToWatchItems,
									withPrometheusAnnotations("9102",
										getCommonAnnotations(v, map[string]string{})))))),
				},
				Spec: podSpec,
			},
			VolumeClaimTemplates: v.Spec.GetVolumeClaimTemplates(),
		},
	}, nil
}

// Annotations Functions

func getCommonAnnotations(v *vaultv1alpha1.Vault, annotations map[string]string) map[string]string {
	for key, value := range v.Spec.GetAnnotations() {
		annotations[key] = value
	}

	return annotations
}

func withPrometheusAnnotations(prometheusPort string, annotations map[string]string) map[string]string {
	if prometheusPort == "" {
		prometheusPort = "9102"
	}

	annotations["prometheus.io/scrape"] = "true"
	annotations["prometheus.io/path"] = "/metrics"
	annotations["prometheus.io/port"] = prometheusPort

	return annotations
}

func withVaultAnnotations(v *vaultv1alpha1.Vault, annotations map[string]string) map[string]string {
	for key, value := range v.Spec.GetVaultAnnotations() {
		annotations[key] = value
	}

	return annotations
}

func withVeleroAnnotations(v *vaultv1alpha1.Vault, annotations map[string]string) map[string]string {
	if v.Spec.VeleroEnabled {
		veleroAnnotations := map[string]string{
			"pre.hook.backup.velero.io/container":  "velero-fsfreeze",
			"pre.hook.backup.velero.io/command":    "[\"/sbin/fsfreeze\", \"--freeze\", \"/vault/file/\"]",
			"post.hook.backup.velero.io/container": "velero-fsfreeze",
			"post.hook.backup.velero.io/command":   "[\"/sbin/fsfreeze\", \"--unfreeze\", \"/vault/file/\"]",
		}

		for key, value := range veleroAnnotations {
			annotations[key] = value
		}
	}

	return annotations
}

func withVaultConfigurerAnnotations(v *vaultv1alpha1.Vault, annotations map[string]string) map[string]string {
	for key, value := range v.Spec.GetVaultConfigurerAnnotations() {
		annotations[key] = value
	}

	return annotations
}

func withVaultWatchedExternalSecrets(v *vaultv1alpha1.Vault, secrets []corev1.Secret, annotations map[string]string) map[string]string {
	if len(secrets) == 0 {
		// No Labels Selector was defined in the spec , return the annotations without changes
		return annotations
	}

	// Calucalte SHASUM of all data fields in all secrets
	secretValues := []string{}
	for _, secret := range secrets {
		for key, value := range secret.Data {
			secretValues = append(secretValues, key+"="+string(value[:]))
		}
	}

	sort.Strings(secretValues)

	h := hmac.New(sha256.New, []byte(""))
	h.Write([]byte(strings.Join(secretValues, ";;")))

	// Set the Annotation
	annotations["vault.banzaicloud.io/watched-secrets-sum"] = fmt.Sprintf("%x", h.Sum(nil))

	return annotations
}

func withTLSExpirationAnnotations(tlsAnnotations, annotations map[string]string) map[string]string {
	for key, value := range tlsAnnotations {
		annotations[key] = value
	}

	return annotations
}

// TLS Functions
func withTLSEnv(v *vaultv1alpha1.Vault, localhost bool, envs []corev1.EnvVar) []corev1.EnvVar {
	host := fmt.Sprintf("%s.%s", v.Name, v.Namespace)
	if localhost {
		host = "127.0.0.1"
	}
	if !v.Spec.IsTLSDisabled() {
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
	if !v.Spec.IsTLSDisabled() {
		if v.Spec.ExistingTLSSecretName != "" {
			volumes = append(volumes, corev1.Volume{
				Name: "vault-tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: v.Spec.ExistingTLSSecretName,
						Items: []corev1.KeyToPath{
							{
								Key:  "ca.crt",
								Path: "ca.crt",
							},
							{
								Key:  "tls.crt",
								Path: "server.crt",
							},
							{
								Key:  "tls.key",
								Path: "server.key",
							},
						},
					},
				},
			})
		} else {
			volumes = append(volumes, corev1.Volume{
				Name: "vault-tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: v.Name + "-tls",
					},
				},
			})
		}
	}
	return volumes
}

func withTLSVolumeMount(v *vaultv1alpha1.Vault, volumeMounts []corev1.VolumeMount) []corev1.VolumeMount {
	if !v.Spec.IsTLSDisabled() {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "vault-tls",
			MountPath: "/vault/tls",
		})
	}
	return volumeMounts
}

func configMapForStatsD(v *vaultv1alpha1.Vault) *corev1.ConfigMap {
	ls := v.LabelsForVault()
	cm := &corev1.ConfigMap{
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
	ls := v.LabelsForVault()
	cm := &corev1.ConfigMap{
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

// withClusterAddr overrides cluster_addr with the env var in multi-cluster deployments
func withClusterAddr(v *vaultv1alpha1.Vault, service *corev1.Service, envs []corev1.EnvVar) []corev1.EnvVar {
	value := ""
	ingressPoints := loadBalancerIngressPoints(service)

	if len(ingressPoints) > 0 {
		value = ingressPoints[len(ingressPoints)-1]
	}

	// Only applies to multi-cluster setups:
	// This currently allows only one instance per cluster,
	// since the cluster_addr is bound to the LB address.
	// Possible workaround: 1 LB/Vault member instance.
	if value != "" && v.Spec.RaftLeaderAddress != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_CLUSTER_ADDR",
			Value: "https://" + value + ":8201",
		})
		envs = append(envs, corev1.EnvVar{
			Name:  "VAULT_API_ADDR",
			Value: v.Spec.GetAPIScheme() + "://" + value + ":8200",
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
	if !v.Spec.IsStatsDDisabled() {
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

func withVaultInitContainers(v *vaultv1alpha1.Vault, containers []corev1.Container) []corev1.Container {
	return append(containers, v.Spec.VaultInitContainers...)
}

func withVeleroContainer(v *vaultv1alpha1.Vault, containers []corev1.Container) []corev1.Container {
	if v.Spec.VeleroEnabled {
		containers = append(containers, corev1.Container{
			Image:           v.Spec.GetVeleroFsfreezeImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Name:            "velero-fsfreeze",
			Command:         []string{"/bin/bash", "-c", "sleep infinity"},
			VolumeMounts:    withVaultVolumeMounts(v, nil),
			SecurityContext: &corev1.SecurityContext{
				Privileged: pointer.BoolPtr(true),
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("32Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("32Mi"),
				},
			},
		})
	}
	return containers
}

func withStatsDContainer(v *vaultv1alpha1.Vault, containers []corev1.Container) []corev1.Container {
	if !v.Spec.IsStatsDDisabled() {
		containers = append(containers, corev1.Container{
			Image:           v.Spec.GetStatsDImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Name:            "prometheus-exporter",
			Args:            []string{"--statsd.mapping-config=/tmp/statsd-mapping.conf"},
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
			Resources: getPrometheusExporterResource(v),
			Env:       withSidecarEnv(v, []v1.EnvVar{}),
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

func withAuditLogContainer(v *vaultv1alpha1.Vault, containers []corev1.Container) []corev1.Container {
	if v.Spec.IsFluentDEnabled() {
		containers = append(containers, corev1.Container{
			Image:           v.Spec.GetFluentDImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Name:            "auditlog-exporter",
			VolumeMounts: withCredentialsVolumeMount(v, []corev1.VolumeMount{
				{
					Name:      "vault-auditlogs",
					MountPath: "/vault/logs",
				},
				{
					Name:      "fluentd-config",
					MountPath: v.Spec.GetFluentDConfMountPath(),
				},
			}),
			Resources: getFluentDResource(v),
			Env:       withSidecarEnv(v, []v1.EnvVar{}),
		})
	}
	return containers
}

// Share the PCSLite Unix Socket across the host:
// https://salsa.debian.org/rousseau/PCSC/blob/master/src/pcscd.h.in#L50
func withHSMVolume(v *vaultv1alpha1.Vault, volumes []corev1.Volume) []corev1.Volume {
	if v.Spec.UnsealConfig.HSMDaemonNeeded() {
		volumes = append(volumes, corev1.Volume{
			Name: "hsm-pcscd",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run/pcscd/",
				},
			},
		})
	}
	return volumes
}

func withHSMVolumeMount(v *vaultv1alpha1.Vault, volumeMounts []corev1.VolumeMount) []corev1.VolumeMount {
	if v.Spec.UnsealConfig.HSMDaemonNeeded() {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "hsm-pcscd",
			MountPath: "/var/run/pcscd/",
		})
	}
	return volumeMounts
}

func getPodAntiAffinity(v *vaultv1alpha1.Vault) *corev1.PodAntiAffinity {
	if v.Spec.PodAntiAffinity == "" {
		return nil
	}

	ls := v.LabelsForVault()
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

func getEtcdAffinity(v *vaultv1alpha1.Vault, etcdName string) *corev1.Affinity {
	if v.Spec.EtcdAffinity != nil {
		return v.Spec.EtcdAffinity
	}
	if v.Spec.PodAntiAffinity != "" {
		return &corev1.Affinity{
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{
						LabelSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "etcd", "etcd_cluster": etcdName},
						},
						TopologyKey: v.Spec.PodAntiAffinity,
					},
				},
			},
		}
	}
	return nil
}

func getNodeAffinity(v *vaultv1alpha1.Vault) *corev1.NodeAffinity {
	if v.Spec.NodeAffinity.Size() == 0 {
		return nil
	}
	return &v.Spec.NodeAffinity
}

func getVaultURIScheme(v *vaultv1alpha1.Vault) corev1.URIScheme {
	if v.Spec.IsTLSDisabled() {
		return corev1.URISchemeHTTP
	}
	return corev1.URISchemeHTTPS
}

func withBanksVaultsVolumeMounts(v *vaultv1alpha1.Vault, volumeMounts []corev1.VolumeMount) []corev1.VolumeMount {
	index := map[string]corev1.VolumeMount{}
	for _, v := range append(volumeMounts, v.Spec.BankVaultsVolumeMounts...) {
		index[v.Name] = v
	}

	volumeMounts = []corev1.VolumeMount{}
	for _, v := range index {
		volumeMounts = append(volumeMounts, v)
	}

	sort.Slice(volumeMounts, func(i, j int) bool { return volumeMounts[i].Name < volumeMounts[j].Name })
	return volumeMounts
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

func withCommonEnv(v *vaultv1alpha1.Vault, envs []corev1.EnvVar) []corev1.EnvVar {
	for _, env := range v.Spec.EnvsConfig {
		envs = append(envs, env)
	}

	return envs
}

func withSidecarEnv(v *vaultv1alpha1.Vault, envs []corev1.EnvVar) []corev1.EnvVar {
	for _, env := range v.Spec.SidecarEnvsConfig {
		envs = append(envs, env)
	}

	return envs
}

func withNamespaceEnv(v *vaultv1alpha1.Vault, envs []corev1.EnvVar) []corev1.EnvVar {
	return append(envs, []corev1.EnvVar{
		{
			Name:  "NAMESPACE",
			Value: v.GetObjectMeta().GetNamespace(),
		},
	}...)
}

func withContainerSecurityContext(v *vaultv1alpha1.Vault) *corev1.SecurityContext {
	config := v.Spec.GetVaultConfig()
	if cast.ToBool(config["disable_mlock"]) {
		return &corev1.SecurityContext{}
	}
	return &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{"IPC_LOCK"},
		},
	}
}

func withPodSecurityContext(v *vaultv1alpha1.Vault) *corev1.PodSecurityContext {
	if v.Spec.SecurityContext.Size() == 0 {
		vaultGID := int64(1000)
		return &corev1.PodSecurityContext{
			FSGroup: &vaultGID,
		}
	}
	return &v.Spec.SecurityContext
}

// Extend Labels with Vault User defined ones
// Does not change original labels object but return a new one
func withVaultLabels(v *vaultv1alpha1.Vault, labels map[string]string) map[string]string {
	var l = map[string]string{}
	for key, value := range labels {
		l[key] = value
	}
	for key, value := range v.Spec.GetVaultLabels() {
		l[key] = value
	}

	return l
}

// Extend Labels with Vault Configurer User defined ones
// Does not change original labels object but return a new one
func withVaultConfigurerLabels(v *vaultv1alpha1.Vault, labels map[string]string) map[string]string {
	var l = map[string]string{}
	for key, value := range labels {
		l[key] = value
	}
	for key, value := range v.Spec.GetVaultConfigurerLabels() {
		l[key] = value
	}

	return l
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
	sort.Strings(podNames)
	return podNames
}

// getVaultResource return resource in spec or return pre-defined resource if not configurated
func getVaultResource(v *vaultv1alpha1.Vault) corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.Vault != nil {
		return *v.Spec.Resources.Vault
	}

	return corev1.ResourceRequirements{
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
func getBankVaultsResource(v *vaultv1alpha1.Vault) corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.BankVaults != nil {
		return *v.Spec.Resources.BankVaults
	}

	return corev1.ResourceRequirements{
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
func getEtcdResource(v *vaultv1alpha1.Vault) corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.Etcd != nil {
		return *v.Spec.Resources.Etcd
	}

	return corev1.ResourceRequirements{
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

// getHSMDaemonResource return resource in spec or return pre-defined resource if not configurated
func getHSMDaemonResource(v *vaultv1alpha1.Vault) corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.HSMDaemon != nil {
		return *v.Spec.Resources.HSMDaemon
	}

	return corev1.ResourceRequirements{
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
func getPrometheusExporterResource(v *vaultv1alpha1.Vault) corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.PrometheusExporter != nil {
		return *v.Spec.Resources.PrometheusExporter
	}

	return corev1.ResourceRequirements{
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

// getFluentDResource return resource in spec or return pre-defined resource if not configurated
func getFluentDResource(v *vaultv1alpha1.Vault) corev1.ResourceRequirements {
	if v.Spec.Resources != nil && v.Spec.Resources.FluentD != nil {
		return *v.Spec.Resources.FluentD
	}

	return corev1.ResourceRequirements{
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

func (r *ReconcileVault) distributeCACertificate(v *vaultv1alpha1.Vault, caSecretKey client.ObjectKey) error {
	// Get the current version of the TLS Secret
	var currentSecret corev1.Secret
	err := r.client.Get(context.TODO(), caSecretKey, &currentSecret)
	if err != nil {
		return fmt.Errorf("failed to query current secret for vault: %v", err)
	}

	// We need the CA certificate only
	if currentSecret.Type == v1.SecretTypeTLS {
		currentSecret.Type = v1.SecretTypeOpaque
		delete(currentSecret.Data, v1.TLSCertKey)
		delete(currentSecret.Data, v1.TLSPrivateKeyKey)
		if err := controllerutil.SetControllerReference(v, &currentSecret, r.scheme); err != nil {
			return fmt.Errorf("failed to set current secret controller reference: %v", err)
		}
	} else {
		delete(currentSecret.StringData, "server.crt")
		delete(currentSecret.StringData, "server.key")
		delete(currentSecret.StringData, "ca.key")
		delete(currentSecret.Data, "server.crt")
		delete(currentSecret.Data, "server.key")
		delete(currentSecret.Data, "ca.key")
	}

	var namespaces []string

	if v.Spec.CANamespaces[0] == "*" {
		var namespaceList corev1.NamespaceList
		if err := r.client.List(context.TODO(), &namespaceList, &client.ListOptions{}); err != nil {
			return fmt.Errorf("failed to list namespaces: %v", err)
		}

		for _, namespace := range namespaceList.Items {
			namespaces = append(namespaces, namespace.Name)
		}
	} else {
		namespaces = v.Spec.CANamespaces
	}

	for _, namespace := range namespaces {
		if namespace != v.Namespace {
			currentSecret.SetNamespace(namespace)
			currentSecret.SetResourceVersion("")
			currentSecret.GetObjectMeta().SetUID("")
			currentSecret.SetOwnerReferences(nil)

			err = createOrUpdateObjectWithClient(r.nonNamespacedClient, &currentSecret)
			if apierrors.IsNotFound(err) {
				log.V(2).Info("can't distribute CA secret, namespace doesn't exist", "namespace", namespace)
			} else if err != nil {
				return fmt.Errorf("failed to create CA secret for vault in namespace %s: %v", namespace, err)
			}
		}
	}

	return nil
}

func certHostsAndIPsChanged(v *vaultv1alpha1.Vault, service *corev1.Service, cert *x509.Certificate) bool {
	// TODO very weak check for now
	return len(cert.DNSNames)+len(cert.IPAddresses) != len(hostsAndIPsForVault(v, service))
}

func (r *ReconcileVault) deployConfigurer(v *vaultv1alpha1.Vault, tlsAnnotations map[string]string) error {
	// Create the configmap if it doesn't exist
	cm := configMapForConfigurer(v)

	// Set Vault instance as the owner and controller
	err := controllerutil.SetControllerReference(v, cm, r.scheme)
	if err != nil {
		return err
	}

	err = r.createOrUpdateObject(cm)
	if err != nil {
		return fmt.Errorf("failed to create/update configurer configmap: %v", err)
	}

	externalConfigMaps := corev1.ConfigMapList{}
	externalConfigMapsFilter := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(v.LabelsForVaultConfigurer()),
		Namespace:     v.Namespace,
	}
	if err = r.client.List(context.TODO(), &externalConfigMaps, &externalConfigMapsFilter); err != nil {
		return fmt.Errorf("failed to list configmaps: %v", err)
	}

	externalSecrets := corev1.SecretList{}
	externalSecretsFilter := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(v.LabelsForVaultConfigurer()),
		Namespace:     v.Namespace,
	}
	if err = r.client.List(context.TODO(), &externalSecrets, &externalSecretsFilter); err != nil {
		return fmt.Errorf("failed to list secrets: %v", err)
	}

	// Create the deployment if it doesn't exist
	configurerDep, err := deploymentForConfigurer(v, externalConfigMaps, externalSecrets, tlsAnnotations)
	if err != nil {
		return fmt.Errorf("failed to fabricate deployment: %v", err)
	}

	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, configurerDep, r.scheme); err != nil {
		return err
	}
	err = r.createOrUpdateObject(configurerDep)
	if err != nil {
		return fmt.Errorf("failed to create/update configurer deployment: %v", err)
	}

	// Create the Configurer service if it doesn't exist
	configurerSer := serviceForVaultConfigurer(v)
	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, configurerSer, r.scheme); err != nil {
		return err
	}

	err = r.createOrUpdateObject(configurerSer)
	if err != nil {
		return fmt.Errorf("failed to create/update service: %v", err)
	}

	return nil
}
