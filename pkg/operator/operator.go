package operator

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/bluele/gcache"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/aquasecurity/trivy-operator/pkg/compliance"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport/controller"
	"github.com/aquasecurity/trivy-operator/pkg/exposedsecretreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/metrics"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/plugins"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/rbacassessment"
	"github.com/aquasecurity/trivy-operator/pkg/sbomreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	vcontroller "github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport/controller"
	"github.com/aquasecurity/trivy-operator/pkg/webhook"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	setupLog = log.Log.WithName("operator")
)

// Start starts all registered reconcilers and blocks until the context is canceled.
// Returns an error if there is an error starting any reconciler.
//
//nolint:gocyclo
func Start(ctx context.Context, buildInfo trivyoperator.BuildInfo, operatorConfig etc.Config) error {
	installMode, operatorNamespace, targetNamespaces, err := operatorConfig.ResolveInstallMode()
	if err != nil {
		return fmt.Errorf("resolving install mode: %w", err)
	}
	setupLog.Info("Resolved install mode", "install mode", installMode,
		"operator namespace", operatorNamespace,
		"target namespaces", targetNamespaces,
		"exclude namespaces", operatorConfig.ExcludeNamespaces,
		"target workloads", operatorConfig.GetTargetWorkloads())

	// Set the default manager options.
	skipNameValidation := true
	options := manager.Options{
		Scheme:                 trivyoperator.NewScheme(),
		Metrics:                metricsserver.Options{BindAddress: operatorConfig.MetricsBindAddress},
		HealthProbeBindAddress: operatorConfig.HealthProbeBindAddress,
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{
					&corev1.Secret{},
					&corev1.ServiceAccount{},
				},
			},
		},
		Cache: cache.Options{
			DefaultTransform: func(obj any) (any, error) {
				obj, err := cache.TransformStripManagedFields()(obj)
				if err != nil {
					return obj, err
				}
				if metaObj, ok := obj.(metav1.ObjectMetaAccessor); ok {
					annotations := metaObj.GetObjectMeta().GetAnnotations()
					if annotations != nil {
						delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")
						metaObj.GetObjectMeta().SetAnnotations(annotations)
					}
				}

				if cm, ok := obj.(*corev1.ConfigMap); ok {
					// Strip data from ALL ConfigMaps except the two operator ConfigMaps
					if cm.Name != trivyoperator.PoliciesConfigMapName && cm.Name != trivyoperator.TrivyConfigMapName {
						cm.Data = nil
						cm.BinaryData = nil
					}
				}
				return obj, nil
			},
		},
		Controller: controllerconfig.Controller{SkipNameValidation: &skipNameValidation},
	}

	if operatorConfig.LeaderElectionEnabled {
		options.LeaderElection = operatorConfig.LeaderElectionEnabled
		options.LeaderElectionID = operatorConfig.LeaderElectionID
		options.LeaderElectionNamespace = operatorNamespace
	}

	switch installMode {
	case etc.OwnNamespace:
		// Add support for OwnNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `trivy-operator`).
		setupLog.Info("Constructing client cache", "namespace", operatorNamespace)
		options.Cache.DefaultNamespaces = map[string]cache.Config{operatorNamespace: {}}
	case etc.SingleNamespace, etc.MultiNamespace:
		// Add support for SingleNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default`).
		// Add support for MultiNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default,kube-system`).
		// Note that you may face performance issues when using this mode with a high number of namespaces.
		// More: https://godoc.org/github.com/kubernetes-sigs/controller-runtime/pkg/cache#MultiNamespacedCacheBuilder
		namespaceCacheMap := make(map[string]cache.Config)
		setupLog.Info("Constructing client cache", "namespaces", targetNamespaces)
		for _, namespace := range append(targetNamespaces, operatorNamespace) {
			namespaceCacheMap[namespace] = cache.Config{}
		}
		options.Cache.DefaultNamespaces = namespaceCacheMap
	case etc.AllNamespaces:
		// Add support for AllNamespaces set in OPERATOR_NAMESPACE (e.g. `operators`)
		// and OPERATOR_TARGET_NAMESPACES left blank.
		setupLog.Info("Watching all namespaces")
	default:
		return fmt.Errorf("unrecognized install mode: %v", installMode)
	}

	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kube client config: %w", err)
	}
	// The only reason we're using kubernetes.Clientset is that we need it to read Pod logs,
	// which is not supported by the client returned by the ctrl.Manager.
	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("constructing kube client: %w", err)
	}
	mgr, err := ctrl.NewManager(kubeConfig, options)
	if err != nil {
		return fmt.Errorf("constructing controllers manager: %w", err)
	}

	err = mgr.AddReadyzCheck("ping", healthz.Ping)
	if err != nil {
		return err
	}

	err = mgr.AddHealthzCheck("ping", healthz.Ping)
	if err != nil {
		return err
	}

	configManager := trivyoperator.NewConfigManager(clientSet, operatorNamespace)
	err = configManager.EnsureDefault(ctx)
	if err != nil {
		return err
	}
	compatibleObjectMapper, err := kube.InitCompatibleMgr()
	if err != nil {
		return err
	}
	trivyOperatorConfig, err := configManager.Read(ctx)
	if err != nil {
		return err
	}
	objectResolver := kube.NewObjectResolver(mgr.GetClient(), compatibleObjectMapper)
	limitChecker := jobs.NewLimitChecker(operatorConfig, mgr.GetClient(), trivyOperatorConfig)
	logsReader := kube.NewLogsReader(clientSet)
	secretsReader := kube.NewSecretsReader(mgr.GetClient())
	plugin, pluginContext, err := plugins.NewResolver().
		WithBuildInfo(buildInfo).
		WithNamespace(operatorNamespace).
		WithServiceAccountName(operatorConfig.ServiceAccount).
		WithConfig(trivyOperatorConfig).
		WithClient(mgr.GetClient()).
		WithObjectResolver(&objectResolver).
		GetVulnerabilityPlugin()
	if err != nil {
		return err
	}
	err = plugin.Init(pluginContext)
	if err != nil {
		return err
	}
	pluginConfig, pluginContextConfig := plugins.NewResolver().WithBuildInfo(buildInfo).
		WithNamespace(operatorNamespace).
		WithServiceAccountName(operatorConfig.ServiceAccount).
		WithConfig(trivyOperatorConfig).
		WithClient(mgr.GetClient()).
		WithObjectResolver(&objectResolver).
		GetConfigAuditPlugin()

	if operatorConfig.VulnerabilityScannerEnabled || operatorConfig.ExposedSecretScannerEnabled || operatorConfig.SbomGenerationEnable {
		trivyOperatorConfig.Set(trivyoperator.KeyVulnerabilityScannerEnabled, strconv.FormatBool(operatorConfig.VulnerabilityScannerEnabled))
		trivyOperatorConfig.Set(trivyoperator.KeyExposedSecretsScannerEnabled, strconv.FormatBool(operatorConfig.ExposedSecretScannerEnabled))
		trivyOperatorConfig.Set(trivyoperator.KeyGenerateSbom, strconv.FormatBool(operatorConfig.SbomGenerationEnable))

		wc, err := newWorkloadController(operatorConfig,
			objectResolver,
			limitChecker,
			secretsReader,
			trivyOperatorConfig,
			mgr, plugin, pluginContext)
		if err != nil {
			return err
		}
		if err = wc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup vulnerabilityreport reconciler: %w", err)
		}

		if err = (&vcontroller.ScanJobController{
			Logger:                  ctrl.Log.WithName("reconciler").WithName("scan job"),
			Config:                  operatorConfig,
			ConfigData:              trivyOperatorConfig,
			ObjectResolver:          objectResolver,
			LogsReader:              logsReader,
			Plugin:                  plugin,
			PluginContext:           pluginContext,
			SbomReadWriter:          sbomreport.NewReadWriter(&objectResolver),
			VulnerabilityReadWriter: vulnerabilityreport.NewReadWriter(&objectResolver),
			ExposedSecretReadWriter: exposedsecretreport.NewReadWriter(&objectResolver),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup scan job  reconciler: %w", err)
		}
	}
	var policyLoader policy.Loader
	var checksLoader *controller.ChecksLoader
	if operatorConfig.ConfigAuditScannerEnabled {
		policyLoader = buildPolicyLoader(trivyOperatorConfig)
		checksLoader = controller.NewChecksLoader(
			operatorConfig,
			ctrl.Log.WithName("checks-loader"),
			mgr.GetClient(),
			objectResolver,
			pluginContext,
			pluginConfig,
			policyLoader,
		)
		if err := checksLoader.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("setup MyReconciler: %w", err)
		}
	}

	if operatorConfig.ScannerReportTTL != nil {
		ttlReconciler := &TTLReportReconciler{
			Logger:       ctrl.Log.WithName("reconciler").WithName("ttlreport"),
			PolicyLoader: policyLoader,
			Config:       operatorConfig,
			Client:       mgr.GetClient(),
			Clock:        ext.NewSystemClock(),
		}
		if operatorConfig.ConfigAuditScannerEnabled {
			ttlReconciler.PluginContext = pluginContextConfig
			ttlReconciler.PluginInMemory = pluginConfig
		}
		if err = ttlReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup TTLreport reconciler: %w", err)
		}
	}

	if operatorConfig.ScanSecretTTL != nil {
		secretTTLReconciler := &TTLSecretReconciler{
			Logger: ctrl.Log.WithName("reconciler").WithName("ttlreport"),
			Config: operatorConfig,
			Client: mgr.GetClient(),
			Clock:  ext.NewSystemClock(),
		}
		if err = secretTTLReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup secretTTLReconciler reconciler: %w", err)
		}
	}

	if operatorConfig.WebhookBroadcastURL != "" {
		if err = (&webhook.WebhookReconciler{
			Logger: ctrl.Log.WithName("reconciler").WithName("webhookreporter"),
			Config: operatorConfig,
			Client: mgr.GetClient(),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup webhookreporter: %w", err)
		}
	}
	var gitVersion string
	if version, err := clientSet.ServerVersion(); err == nil {
		gitVersion = strings.TrimPrefix(version.GitVersion, "v")
		gitVersion = strings.ReplaceAll(gitVersion, "+", "-")
	}

	if operatorConfig.ConfigAuditScannerEnabled {
		setupLog.Info("Enabling built-in configuration audit scanner")
		if err = (&controller.ResourceController{
			Logger:           ctrl.Log.WithName("resourcecontroller"),
			Config:           operatorConfig,
			PolicyLoader:     policyLoader,
			ConfigData:       trivyOperatorConfig,
			ObjectResolver:   objectResolver,
			PluginContext:    pluginContext,
			PluginInMemory:   pluginConfig,
			ReadWriter:       configauditreport.NewReadWriter(&objectResolver),
			RbacReadWriter:   rbacassessment.NewReadWriter(&objectResolver),
			InfraReadWriter:  infraassessment.NewReadWriter(&objectResolver),
			BuildInfo:        buildInfo,
			ClusterVersion:   gitVersion,
			CacheSyncTimeout: *operatorConfig.ControllerCacheSyncTimeout,
			ChecksLoader:     checksLoader,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup resource controller: %w", err)
		}
		if err = (&controller.PolicyConfigController{
			Logger:         ctrl.Log.WithName("resourcecontroller"),
			Config:         operatorConfig,
			PolicyLoader:   policyLoader,
			ObjectResolver: objectResolver,
			PluginContext:  pluginContext,
			PluginInMemory: pluginConfig,
			ClusterVersion: gitVersion,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup policy config controller: %w", err)
		}
		if operatorConfig.InfraAssessmentScannerEnabled {
			limitChecker := jobs.NewLimitChecker(operatorConfig, mgr.GetClient(), trivyOperatorConfig)
			if err = (&controller.NodeReconciler{
				Logger:           ctrl.Log.WithName("node-reconciler"),
				Config:           operatorConfig,
				PolicyLoader:     policyLoader,
				ConfigData:       trivyOperatorConfig,
				ObjectResolver:   objectResolver,
				PluginContext:    pluginContext,
				PluginInMemory:   pluginConfig,
				LimitChecker:     limitChecker,
				InfraReadWriter:  infraassessment.NewReadWriter(&objectResolver),
				BuildInfo:        buildInfo,
				CacheSyncTimeout: *operatorConfig.ControllerCacheSyncTimeout,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to setup node collector controller: %w", err)
			}
			if err = (&controller.NodeCollectorJobController{
				Logger:          ctrl.Log.WithName("node-collectorontroller"),
				Config:          operatorConfig,
				ConfigData:      trivyOperatorConfig,
				ObjectResolver:  objectResolver,
				LogsReader:      logsReader,
				PolicyLoader:    policyLoader,
				PluginContext:   pluginContext,
				PluginInMemory:  pluginConfig,
				InfraReadWriter: infraassessment.NewReadWriter(&objectResolver),
				BuildInfo:       buildInfo,
				ChecksLoader:    checksLoader,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to setup node collector controller: %w", err)
			}
		}
	}

	if operatorConfig.ClusterComplianceEnabled {
		logger := ctrl.Log.WithName("reconciler").WithName("clustercompliancereport")
		cc := &compliance.ClusterComplianceReportReconciler{
			Logger: logger,
			Config: operatorConfig,
			Client: mgr.GetClient(),
			Mgr:    compliance.NewMgr(mgr.GetClient()),
			Clock:  ext.NewSystemClock(),
		}
		if err := cc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup clustercompliancereport reconciler: %w", err)
		}
	}

	if operatorConfig.MetricsFindingsEnabled {
		logger := ctrl.Log.WithName("metrics")
		rmc := metrics.NewResourcesMetricsCollector(logger, operatorConfig, trivyOperatorConfig, mgr.GetClient())
		if err := rmc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup resources metrics collector: %w", err)
		}
	}

	if operatorConfig.SbomGenerationEnable && operatorConfig.VulnerabilityScannerEnabled {
		name, err := clusterName()
		if err != nil {
			return fmt.Errorf("fetching cluster details: %w", err)
		}
		wc, err := newWorkloadController(operatorConfig,
			objectResolver,
			limitChecker,
			secretsReader,
			trivyOperatorConfig,
			mgr, plugin, pluginContext)
		if err != nil {
			return err
		}
		cc := &ClusterController{
			name:               name,
			clientset:          clientSet,
			version:            gitVersion,
			clusterCache:       &sync.Map{},
			cacheSyncTimeout:   *operatorConfig.ControllerCacheSyncTimeout,
			WorkloadController: wc,
		}
		if err := cc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup cluster reconciler: %w", err)
		}
	}

	setupLog.Info("Starting controllers manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("starting controllers manager: %w", err)
	}

	return nil
}

func clusterName() (string, error) {
	cf := genericclioptions.NewConfigFlags(true)
	crf := cf.ToRawKubeConfigLoader()
	rawCfg, err := crf.RawConfig()
	if err != nil {
		return "", err
	}
	clusterName := "k8s.io/kubernetes"
	if len(rawCfg.Contexts) > 0 {
		clusterName = rawCfg.Contexts[rawCfg.CurrentContext].Cluster
	}
	return clusterName, nil
}

func newWorkloadController(operatorConfig etc.Config,
	objectResolver kube.ObjectResolver,
	limitChecker jobs.LimitChecker,
	secretsReader kube.SecretsReader,
	trivyOperatorConfig trivyoperator.ConfigData,
	mgr ctrl.Manager,
	plugin vulnerabilityreport.Plugin, pluginContext trivyoperator.PluginContext) (*vcontroller.WorkloadController, error) {

	return &vcontroller.WorkloadController{
		Logger:           ctrl.Log.WithName("reconciler").WithName("vulnerabilityreport"),
		Config:           operatorConfig,
		ConfigData:       trivyOperatorConfig,
		Client:           mgr.GetClient(),
		ObjectResolver:   objectResolver,
		LimitChecker:     limitChecker,
		SecretsReader:    secretsReader,
		Plugin:           plugin,
		PluginContext:    pluginContext,
		CacheSyncTimeout: *operatorConfig.ControllerCacheSyncTimeout,
		ServerHealthChecker: vcontroller.NewTrivyServerChecker(
			operatorConfig.TrivyServerHealthCheckCacheExpiration,
			gcache.New(1).LRU().Build(),
			vcontroller.NewHttpChecker()),
		VulnerabilityReadWriter: vulnerabilityreport.NewReadWriter(&objectResolver),
		ExposedSecretReadWriter: exposedsecretreport.NewReadWriter(&objectResolver),
		SbomReadWriter:          sbomreport.NewReadWriter(&objectResolver),
		SubmitScanJobChan:       make(chan vcontroller.ScanJobRequest, operatorConfig.ConcurrentScanJobsLimit),
		ResultScanJobChan:       make(chan vcontroller.ScanJobResult, operatorConfig.ConcurrentScanJobsLimit),
	}, nil
}

func buildPolicyLoader(tc trivyoperator.ConfigData) policy.Loader {
	registryUser := tc.PolicyBundleOciUser()
	registryPassword := tc.PolicyBundleOciPassword()
	ro := types.RegistryOptions{}
	if registryUser != "" && registryPassword != "" {
		ro.Credentials = []types.Credential{
			{
				Username: registryUser,
				Password: registryPassword,
			},
		}
	}
	ro.Insecure = tc.PolicyBundleInsecure()
	return policy.NewPolicyLoader(tc.PolicyBundleOciRef(), gcache.New(2).LRU().Build(), ro)
}
