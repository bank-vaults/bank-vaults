package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/banzaicloud/bank-vaults/pkg/kv/k8s"
	"github.com/banzaicloud/bank-vaults/pkg/tls"
	"github.com/banzaicloud/bank-vaults/pkg/vault"
	vaultv1alpha1 "github.com/banzaicloud/bank-vaults/vault-operator/pkg/apis/vault/v1alpha1"
	etcdV1beta2 "github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	"github.com/coreos/etcd-operator/pkg/util/etcdutil"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	return &ReconcileVault{client: mgr.GetClient(), scheme: mgr.GetScheme()}
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

	//// TODO(user): Modify this to be the types you create that are owned by the primary resource
	//// Watch for changes to secondary resource Pods and requeue the owner Vault
	//err = c.Watch(&source.Kind{Type: &corev1.Pod{}}, &handler.EnqueueRequestForOwner{
	//	IsController: true,
	//	OwnerType:    &vaultv1alpha1.Vault{},
	//})
	//if err != nil {
	//	return err
	//}

	return nil
}

var _ reconcile.Reconciler = &ReconcileVault{}

// ReconcileVault reconciles a Vault object
type ReconcileVault struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
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


		err = r.client.Create(context.TODO(),sec)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return reconcile.Result{}, fmt.Errorf("failed to create secret for etcd: %v", err)
		}

		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, etcdCluster, r.scheme); err != nil {
			return reconcile.Result{}, err
		}

		err = r.client.Create(context.TODO(), etcdCluster)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return reconcile.Result{}, fmt.Errorf("failed to create etcd cluster: %v", err)
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

		err = r.client.Create(context.TODO(),sec)
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return reconcile.Result{}, fmt.Errorf("failed to create secret for vault: %v", err)
		}
	}

	// Create the configmap if it doesn't exist
	cm := configMapForStatsD(v)

	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, cm, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	err = r.client.Create(context.TODO(), cm)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return reconcile.Result{}, fmt.Errorf("failed to create statsd configmap: %v", err)
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

	err = r.client.Get(context.TODO(),request.NamespacedName, statefulSet)
	if err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.client.Create(context.TODO(), statefulSet); err != nil {
				return reconcile.Result{}, fmt.Errorf("failed to create StatefulSet: %v", err)
			}
		} else {
			return reconcile.Result{}, fmt.Errorf("failed to get StatefulSet: %v", err)
		}
	} else {
		newStatefulSet, err := statefulSetForVault(v)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to fabricate StatefulSet: %v", err)
		}
		// Set Vault instance as the owner and controller
		if err := controllerutil.SetControllerReference(v, newStatefulSet, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		statefulSet.Spec = newStatefulSet.Spec
		err = r.client.Update(context.TODO(), statefulSet)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update StatefulSet: %v", err)
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
	if !reflect.DeepEqual(podNames, v.Status.Nodes) {
		v.Status.Nodes = podNames
		err := r.client.Update(context.TODO(), v)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update vault status: %v", err)
		}
	}

	// Create the service if it doesn't exist
	ser := serviceForVault(v)
	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, ser, r.scheme); err != nil {
		return reconcile.Result{}, err
	}
	err = r.client.Create(context.TODO(), ser)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return reconcile.Result{}, fmt.Errorf("failed to create service: %v", err)
	}

	// Create the deployment if it doesn't exist
	configurerDep := deploymentForConfigurer(v)
	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, configurerDep, r.scheme); err != nil {
		return reconcile.Result{}, err
	}
	err = r.client.Create(context.TODO(), configurerDep)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return reconcile.Result{}, fmt.Errorf("failed to create configurer deployment: %v", err)
	}
	logDeployment(configurerDep)

	// Create the configmap if it doesn't exist
	cm = configMapForConfigurer(v)

	// Set Vault instance as the owner and controller
	if err := controllerutil.SetControllerReference(v, cm, r.scheme); err != nil {
		return reconcile.Result{}, err
	}
	err = r.client.Create(context.TODO(), cm)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return reconcile.Result{}, fmt.Errorf("failed to create configurer configmap: %v", err)
	}

	// Ensure the configmap is the same as the spec
	err = r.client.Get(context.TODO(), request.NamespacedName, cm)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get deployment: %v", err)
	}

	externalConfig := v.Spec.ExternalConfigJSON()
	if cm.Data[vault.DefaultConfigFile] != externalConfig {
		cm.Data[vault.DefaultConfigFile] = externalConfig
		err = r.client.Update(context.TODO(), cm)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update configurer configmap: %v", err)
		}
	}

	return reconcile.Result{}, nil
}

func logDeployment(dep *appsv1.Deployment) error {
	data, err := json.Marshal(dep)
	if err != nil {
		return fmt.Errorf("failed to marshal the deployment object: %v", err)
	}
	var prettyData bytes.Buffer
	err = json.Indent(&prettyData, data, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to indent the content: %v", err)
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.Debugln("Deployed:")
		// use println because the logrus formatter is messing up the JSON indet
		fmt.Println(string(prettyData.Bytes()))
	}
	return nil
}

func secretForEtcd(e *etcdV1beta2.EtcdCluster) (*corev1.Secret, error) {
	hosts := []string{
		e.Name,
		e.Name + "." + e.Namespace,
		"*." + e.Name + "." + e.Namespace + ".svc",
		e.Name + "-client." + e.Namespace + ".svc",
		"localhost",
	}
	chain, err := tls.GenerateTLS(strings.Join(hosts, ","), "8760h")
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

func etcdForVault(v *vaultv1alpha1.Vault) (*etcdV1beta2.EtcdCluster, error) {
	storage := v.Spec.GetStorage()
	etcdAddress := storage["address"].(string)
	etcdURL, err := url.Parse(etcdAddress)
	if err != nil {
		return nil, err
	}
	etcdName := etcdURL.Hostname()
	etcdCluster := &etcdV1beta2.EtcdCluster{}
	etcdCluster.APIVersion = etcdV1beta2.SchemeGroupVersion.String()
	etcdCluster.Kind = etcdV1beta2.EtcdClusterResourceKind
	etcdCluster.Annotations = v.Spec.EtcdAnnotations
	etcdCluster.Name = etcdName
	etcdCluster.Namespace = v.Namespace
	etcdCluster.Labels = labelsForVault(v.Name)
	etcdCluster.Spec.Size = v.Spec.GetEtcdSize()
	etcdCluster.Spec.Version = v.Spec.GetEtcdVersion()
	etcdCluster.Spec.TLS = &etcdV1beta2.TLSPolicy{
		Static: &etcdV1beta2.StaticTLS{
			OperatorSecret: etcdName + "-tls",
			Member: &etcdV1beta2.MemberSecret{
				ServerSecret: etcdName + "-tls",
				PeerSecret:   etcdName + "-tls",
			},
		},
	}

	return etcdCluster, nil
}

func serviceForVault(v *vaultv1alpha1.Vault) *corev1.Service {
	ls := labelsForVault(v.Name)
	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      v.Name,
			Namespace: v.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     serviceType(v),
			Selector: ls,
			Ports: []corev1.ServicePort{
				{
					Name: "api-port",
					Port: 8200,
				},
				{
					Name: "cluster-port",
					Port: 8201,
				},
			},
		},
	}
	return service
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
		return corev1.ServiceTypeNodePort
	}
}

func deploymentForConfigurer(v *vaultv1alpha1.Vault) *appsv1.Deployment {
	ls := labelsForVaultConfigurer(v.Name)
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
					Annotations: v.Spec.Annotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: v.Spec.GetServiceAccount(),
					Containers: []corev1.Container{
						{
							Image:           v.Spec.GetBankVaultsImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "bank-vaults",
							Command:         []string{"bank-vaults", "configure"},
							Args:            v.Spec.UnsealConfig.ToArgs(v),
							Env:             withSecretEnv(v, withTLSEnv(v, false, withCredentialsEnv(v, []corev1.EnvVar{}))),
							VolumeMounts: withTLSVolumeMount(v, withCredentialsVolumeMount(v, []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/config",
								},
							})),
							WorkingDir: "/config",
						},
					},
					Volumes: withTLSVolume(v, withCredentialsVolume(v, []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: v.Name + "-configurer"},
								},
							},
						},
					})),
					SecurityContext: withSecurityContext(v),
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
	chain, err := tls.GenerateTLS(hostsAndIPs, "8760h")
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
		return nil, fmt.Errorf("More than 1 replicas are not supported without HA storage backend")
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
		{
			Name: "statsd-mapping",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: v.Name + "-statsd-mapping"},
				},
			},
		},
	}))

	volumes = withAuditLogVolume(v, volumes)

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
					Annotations: v.Spec.GetAnnotations(),
				},
				Spec: corev1.PodSpec{
					Affinity:           getPodAntiAffinity(v),
					ServiceAccountName: v.Spec.GetServiceAccount(),
					Containers: withAuditLogContainer(v, string(ownerJSON), []corev1.Container{
						{
							Image:           v.Spec.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "vault",
							Args:            []string{"server", "-log-level=debug"},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 8200,
									Name:          "api-port",
								},
								{
									ContainerPort: 8201,
									Name:          "cluster-port",
								}},
							Env: withTLSEnv(v, true, withCredentialsEnv(v, withVaultEnv(v, []corev1.EnvVar{
								{
									Name:  "VAULT_LOCAL_CONFIG",
									Value: configJSON,
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
										Path:   "/v1/sys/health",
									}},
								PeriodSeconds:    5,
								FailureThreshold: 2,
							},
							VolumeMounts: withVaultVolumeMounts(v, volumeMounts),
						},
						{
							Image:           v.Spec.GetBankVaultsImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "bank-vaults",
							Command:         withSupportUpgradeParams(v, []string{"bank-vaults", "unseal", "--init"}),
							Args:            v.Spec.UnsealConfig.ToArgs(v),
							Env: withSecretEnv(v, withTLSEnv(v, true, withCredentialsEnv(v, []corev1.EnvVar{
								{
									Name:  k8s.EnvK8SOwnerReference,
									Value: string(ownerJSON),
								},
							}))),
							VolumeMounts: withTLSVolumeMount(v, withCredentialsVolumeMount(v, []corev1.VolumeMount{})),
						},
						{
							Image:           v.Spec.GetStatsDImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "prometheus-exporter",
							Args:            []string{"--statsd.mapping-config=/tmp/statsd-mapping.conf"},
							Env: withTLSEnv(v, true, withCredentialsEnv(v, []corev1.EnvVar{
								{
									Name:  k8s.EnvK8SOwnerReference,
									Value: string(ownerJSON),
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
						},
					}),
					Volumes:         withVaultVolumes(v, volumes),
					SecurityContext: withSecurityContext(v),
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

func withAuditLogVolume(v *vaultv1alpha1.Vault, volumes []corev1.Volume) []corev1.Volume {
	if v.Spec.IsFluentDEnabled() {
		volumes = append(volumes, corev1.Volume{
			Name: "vault-auditlogs",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}
	return volumes
}

func withAuditLogVolumeMount(v *vaultv1alpha1.Vault, volumeMounts []corev1.VolumeMount) []corev1.VolumeMount {
	if v.Spec.IsFluentDEnabled() {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "vault-auditlogs",
			MountPath: "/tmp/",
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
			Env: withTLSEnv(v, true, withCredentialsEnv(v, []corev1.EnvVar{
				{
					Name:  k8s.EnvK8SOwnerReference,
					Value: owner,
				},
			})),
			VolumeMounts: withTLSVolumeMount(v, withCredentialsVolumeMount(v, []corev1.VolumeMount{
				{
					Name:      "vault-auditlogs",
					MountPath: "/tmp/",
				},
			})),
		})
	}
	return containers
}

func getPodAntiAffinity(v *vaultv1alpha1.Vault) *corev1.Affinity {
	if v.Spec.PodAntiAffinity == "" {
		return nil
	}

	ls := labelsForVault(v.Name)
	return &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: ls,
					},
					TopologyKey: v.Spec.PodAntiAffinity,
				},
			},
		},
	}
}

func withSupportUpgradeParams(v *vaultv1alpha1.Vault, params []string) []string {
	if v.Spec.SupportUpgrade {
		host := fmt.Sprintf("%s.%s", v.Name, v.Namespace)
		address := fmt.Sprintf("https://%s:8200", host)
		params = append(params, []string{"--step-down-active", "--active-node-address", address}...)
	}
	return params
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
