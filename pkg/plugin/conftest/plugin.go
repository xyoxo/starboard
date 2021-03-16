package conftest

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/plugin/conftest/aquascope"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"io"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
	"strings"
)

const (
	conftestContainerName = "conftest"
)

// KAPPolicy represents a Kubernetes assurance policy.
type KAPPolicy struct {
	Name     string          // Name is the name of this policy
	Scope    aquascope.Scope // Scope is the expression that we evaluate to check if this policy applicable to a given K8s object.
	Controls []KAPControl
}

type KAPControl struct {
	Name string // Name is the title of the corresponding Rego script.
}

const (
	kubernetesAttribute          = "kubernetes"
	kubernetesNamespaceAttribute = "kubernetes.namespace"
	kubernetesClusterAttribute   = "kubernetes.cluster"
	kubernetesPodAttribute       = "kubernetes.pod"
	kubernetesLabelAttribute     = "kubernetes.label"
)

func GetKubernetesScopeAttributes(obj client.Object) map[string]string {
	result := make(map[string]string)

	result[fmt.Sprintf("%s.%s", kubernetesAttribute, strings.ToLower(obj.GetObjectKind().GroupVersionKind().Kind))] = obj.GetName()
	result[kubernetesNamespaceAttribute] = obj.GetNamespace()
	// result[kubernetesClusterAttribute] = ctx.resource.ClusterName
	result[kubernetesPodAttribute] = obj.GetName()

	for key, value := range obj.GetLabels() {
		result[fmt.Sprintf("%s.%s", kubernetesLabelAttribute, key)] = value
	}

	return result
}

func GetMatchedKAPolicies(policies []KAPPolicy, obj client.Object) (result []KAPPolicy) {
	containerVariables := GetKubernetesScopeAttributes(obj)

	for _, policy := range policies {
		if len(policy.Scope.Variables) == 0 {
			continue
		}

		match, err := IsScopeMatch(policy.Scope, containerVariables)
		if err != nil {
			// ctx.logger.Warn(fmt.Sprintf("Failed matching scope: %s", err))
			continue
		}

		if match {
			//ctx.logger.Debug(fmt.Sprintf("%s %s matched policy %s", ctx.resource.Kind, ctx.resource.Name, policy.Name))

			result = append(result, policy)
		}
	}

	return result
}

func IsScopeMatch(scope aquascope.Scope, variables map[string]string) (bool, error) {
	if scope.Expression == "" {
		return false, nil
	}

	for i := range scope.Variables {
		scope.Variables[i].Value = strings.Trim(scope.Variables[i].Value, "\"'")
	}

	var processedValueVars []aquascope.Variable

	for i := 0; i < len(scope.Variables); i++ {
		variableName := scope.Variables[i].Name

		if scope.Variables[i].Attribute == kubernetesLabelAttribute {
			markedAttribute := fmt.Sprintf("%s.%s", kubernetesLabelAttribute, variableName)

			if value, found := variables[markedAttribute]; found {
				processedValueVars = append(processedValueVars, aquascope.Variable{
					Attribute: markedAttribute,
					Name:      variableName,
					Value:     value,
				})

				delete(variables, markedAttribute)
			}

			scope.Variables[i].Attribute = markedAttribute
		}
	}

	// Create eval context with changed scope attributes, for multi-value variables
	eval := aquascope.StartEval(scope)

	// Add processed multivalue
	for _, variable := range processedValueVars {
		// WithValue & WithNameValue are the same, except WithNameValue set the name too.
		// for multi valued attributes, we add unique attribute and its name, value using WithNameValue method
		eval.WithNameValue(variable.Attribute, variable.Name, variable.Value)
	}

	for attribute, value := range variables {
		eval.WithValue(attribute, value)
	}

	return eval.Check()
}

type Config interface {
	GetConftestImageRef() (string, error)
}

type plugin struct {
	idGenerator ext.IDGenerator
	clock       ext.Clock
	config      Config
}

// NewPlugin constructs a new configauditreport.Plugin, which is using an
// official Conftest container image to audit Kubernetes workloads.
func NewPlugin(clock ext.Clock, config Config) configauditreport.Plugin {
	return &plugin{
		idGenerator: ext.NewGoogleUUIDGenerator(),
		clock:       clock,
		config:      config,
	}
}

func GetKAPPoliciesFromConfigMap(cm *corev1.ConfigMap) ([]KAPPolicy, error) {
	policies := map[string]*KAPPolicy{}

	for k, v := range cm.Data {
		if !strings.HasPrefix(k, "conftest.policy.") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(k, "conftest.policy."), ".")
		policyName := parts[0]
		var policy *KAPPolicy
		var exists bool

		policy, exists = policies[policyName]
		// Add policy with the given name to map if it does not exist
		if !exists {
			policy = &KAPPolicy{Name: policyName, Controls: []KAPControl{}}
			policies[policyName] = policy
		}

		// If the key is for scope unmarshall it and save
		if len(parts) == 2 && parts[1] == "scope" {
			err := json.Unmarshal([]byte(v), &policy.Scope)
			if err != nil {
				return nil, fmt.Errorf("unmarshalling scope: %w", err)
			}
		}

		// this must be control name
		if len(parts) >= 2 && parts[1] != "scope" {
			policy.Controls = append(policy.Controls, KAPControl{Name: strings.Join(parts[1:], ".")})
		}

	}

	var result []KAPPolicy
	for _, v := range policies {
		result = append(result, *v)
	}
	return result, nil
}

func (p *plugin) GetKAPPolicies(ctx starboard.PluginContext) ([]KAPPolicy, error) {
	cm, err := ctx.GetConfigMapByName("conftestconfig")
	if err != nil {
		return nil, err
	}
	return GetKAPPoliciesFromConfigMap(cm)
}

func (p *plugin) GetScanJobSpec(ctx starboard.PluginContext, _ kube.Object, obj client.Object, gvk schema.GroupVersionKind) (corev1.PodSpec, []*corev1.Secret, error) {
	imageRef, err := p.config.GetConftestImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	var secrets []*corev1.Secret

	// TODO This is a workaround to set GVK and serialize to YAML properly
	obj.GetObjectKind().SetGroupVersionKind(gvk)

	workloadAsYAML, err := yaml.Marshal(obj)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.idGenerator.GenerateID(),
		},
		StringData: map[string]string{
			"workload.yaml": string(workloadAsYAML),
		},
	}

	secrets = append(secrets, secret)

	policies, err := p.GetKAPPolicies(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	policies = GetMatchedKAPolicies(policies, obj)

	var volumeMounts []corev1.VolumeMount
	var volumeItems []corev1.KeyToPath

	controlNames := make(map[string]bool)

	for _, policy := range policies {
		for _, control := range policy.Controls {
			if _, loaded := controlNames[control.Name]; loaded {
				fmt.Printf(">>>>> Already loaded: %s <<<<<<\n", control.Name)
				continue
			}

			volumeItems = append(volumeItems, corev1.KeyToPath{
				Key:  "conftest.policy." + policy.Name + "." + control.Name,
				Path: policy.Name + "_" + control.Name + ".rego",
			})

			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      "policies",
				MountPath: "/project/policy/" + policy.Name + "_" + control.Name + ".rego",
				SubPath:   policy.Name + "_" + control.Name + ".rego",
			})

			controlNames[control.Name] = true
		}
	}

	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      secret.Name,
		MountPath: "/project/workload.yaml",
		SubPath:   "workload.yaml",
	})

	return corev1.PodSpec{
		ServiceAccountName:           starboard.ServiceAccountName,
		AutomountServiceAccountToken: pointer.BoolPtr(true),
		RestartPolicy:                corev1.RestartPolicyNever,
		Affinity:                     starboard.LinuxNodeAffinity(),
		Volumes: []corev1.Volume{
			{
				Name: "policies",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "conftestconfig",
						},
						Items: volumeItems,
					},
				},
			},
			{
				Name: secret.Name,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secret.Name,
					},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:                     conftestContainerName,
				Image:                    imageRef,
				ImagePullPolicy:          corev1.PullIfNotPresent,
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("300m"),
						corev1.ResourceMemory: resource.MustParse("300M"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("50M"),
					},
				},
				VolumeMounts: volumeMounts,
				Command: []string{
					"sh",
				},
				Args: []string{
					"-c",
					"conftest test --output json --policy /project/policy /project/workload.yaml || true",
				},
				SecurityContext: &corev1.SecurityContext{
					Privileged:               pointer.BoolPtr(false),
					AllowPrivilegeEscalation: pointer.BoolPtr(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"all"},
					},
					ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				},
			},
		},
		SecurityContext: &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(1000),
			RunAsGroup: pointer.Int64Ptr(1000),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
	}, secrets, nil

}

func (p *plugin) GetContainerName() string {
	return conftestContainerName
}

const (
	defaultCategory = "Security"
)

func (p *plugin) ParseConfigAuditResult(logsReader io.ReadCloser) (v1alpha1.ConfigAuditResult, error) {
	var checkResults []CheckResult
	err := json.NewDecoder(logsReader).Decode(&checkResults)

	var checks []v1alpha1.Check
	var successesCount, warningCount, dangerCount int

	for _, cr := range checkResults {
		successesCount += cr.Successes

		for _, warning := range cr.Warnings {
			checks = append(checks, v1alpha1.Check{
				ID:       p.getPolicyTitleFromResult(warning),
				Severity: "WARNING",
				Message:  warning.Message,
				Category: defaultCategory,
				Success:  false,
			})
			warningCount++
		}

		for _, failure := range cr.Failures {
			checks = append(checks, v1alpha1.Check{
				ID:       p.getPolicyTitleFromResult(failure),
				Severity: "DANGER",
				Message:  failure.Message,
				Category: defaultCategory,
			})
			dangerCount++
		}
	}

	imageRef, err := p.config.GetConftestImageRef()
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	version, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.ConfigAuditResult{}, err
	}

	return v1alpha1.ConfigAuditResult{
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Conftest",
			Vendor:  "Open Policy Agent",
			Version: version,
		},
		Summary: v1alpha1.ConfigAuditSummary{
			PassCount:    successesCount, // TODO This should be a pointer to tell 0 from nil
			WarningCount: warningCount,
			DangerCount:  dangerCount,
		},
		PodChecks:       checks,
		ContainerChecks: map[string][]v1alpha1.Check{},
	}, nil
}

func (p *plugin) getPolicyTitleFromResult(result Result) string {
	if title, ok := result.Metadata["title"]; ok {
		return title.(string)
	}
	// Fallback to a unique identifier
	return p.idGenerator.GenerateID()
}
