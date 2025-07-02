package controller

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8spredicate "sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

type PolicyManager interface {
	GetPolicies(ctx context.Context) (*policy.Policies, error)
}

type ChecksController struct {
	mu             sync.Mutex
	cfg            etc.Config
	logger         logr.Logger
	cl             client.Client
	objectResolver kube.ObjectResolver
	pluginContext  trivyoperator.PluginContext
	pluginConfig   configauditreport.PluginInMemory
	policyLoader   policy.Loader
	policies       *policy.Policies
}

func NewChecksLoader(
	cfg etc.Config,
	logger logr.Logger,
	cl client.Client,
	objectResolver kube.ObjectResolver,
	pluginContext trivyoperator.PluginContext,
	pluginConfig configauditreport.PluginInMemory,
	policyLoader policy.Loader,
) *ChecksController {
	return &ChecksController{
		cfg:            cfg,
		logger:         logger,
		cl:             cl,
		objectResolver: objectResolver,
		pluginContext:  pluginContext,
		pluginConfig:   pluginConfig,
		policyLoader:   policyLoader,
	}
}

func (r *ChecksController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	log := r.logger.WithValues("configMap", req.NamespacedName)

	var cm corev1.ConfigMap
	if err := r.cl.Get(ctx, req.NamespacedName, &cm); err != nil {
		if req.Name == trivyoperator.TrivyConfigMapName {
			log.V(1).Info("Checks removed since trivy config is removed")
			r.policies = nil
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.loadChecks(ctx); err != nil {
		return ctrl.Result{}, fmt.Errorf("load checks: %w", err)
	}

	// Create ConfigScanRequest - a single signal for PolicyConfigController
	scanReq := &v1alpha1.ConfigScanRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "configscanrequest-",
			Namespace:    r.cfg.Namespace,
		},
	}

	if err := r.cl.Create(ctx, scanReq); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("create ConfigScanRequest: %w", err)
		}
	}

	log.V(1).Info("Created ConfigScanRequest to trigger report deletion and scanning", "configScanRequest", scanReq.Name)
	return ctrl.Result{}, nil
}

func (r *ChecksController) loadChecks(ctx context.Context) error {
	r.logger.V(1).Info("Load checks")
	cac, err := r.pluginConfig.NewConfigForConfigAudit(r.pluginContext)
	if err != nil {
		return fmt.Errorf("new config for config audit: %w", err)
	}
	policies, err := ConfigurePolicies(
		ctx, r.cfg, r.objectResolver, cac, r.logger, r.policyLoader,
	)
	if err != nil {
		return fmt.Errorf("getting policies: %w", err)
	}
	r.policies = policies
	r.logger.V(1).Info("Checks loaded")
	return nil
}

// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=configscanrequests,verbs=create

func (r *ChecksController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}, builder.WithPredicates(
			k8spredicate.Or(
				predicate.HasName(trivyoperator.TrivyConfigMapName),
				predicate.HasName(trivyoperator.PoliciesConfigMapName),
			),
			predicate.InNamespace(r.cfg.Namespace),
		)).
		Complete(r)
}

func (r *ChecksController) GetPolicies(ctx context.Context) (*policy.Policies, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.policies == nil {
		if err := r.loadChecks(ctx); err != nil {
			return nil, fmt.Errorf("load checks: %w", err)
		}
	}

	return r.policies, nil
}
