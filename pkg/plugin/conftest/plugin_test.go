package conftest_test

import (
	"testing"

	"github.com/aquasecurity/starboard/pkg/plugin/conftest"
	"github.com/aquasecurity/starboard/pkg/plugin/conftest/aquascope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetKAPPoliciesFromConfigMap(t *testing.T) {
	cm := corev1.ConfigMap{
		Data: map[string]string{
			"conftest.policy.demo1.kubernetes.rego":                   "<REGO>",
			"conftest.policy.demo1.root_file_system_is_not_read-only": "<REGO>",
			"conftest.policy.demo1.image_tag_latest_used":             "<REGO>",
			"conftest.policy.demo1.scope":                             `{"expression":"v1","variables":[{"attribute":"kubernetes.pod","value":"*"}]}`,

			"conftest.policy.demo2-test.kubernetes.rego":                   "<REGO>",
			"conftest.policy.demo2-test.manages_etchosts":                  "<REGO>",
			"conftest.policy.demo2-test.root_file_system_is_not_read-only": "<REGO>",
			"conftest.policy.demo2-test.image_tag_latest_used":             "<REGO>",
			"conftest.policy.demo2-test.scope":                             `{"expression":"v1","variables":[{"attribute":"kubernetes.namespace","value":"kapns"}]}`,
		},
	}
	policies, err := conftest.GetKAPPoliciesFromConfigMap(cm)
	require.NoError(t, err)
	assert.NotNil(t, policies) // TODO Use smart assert

	//assert.Equal(t, []conftest.KAPPolicy{
	//	{
	//		Name: "demo1",
	//		Scope: aquascope.Scope{
	//			Expression: "v1",
	//			Variables: []aquascope.Variable{
	//				{
	//					Attribute: "kubernetes.pod",
	//					Value:     "*",
	//				},
	//			},
	//		},
	//		Controls: []conftest.KAPControl{
	//			{
	//				Name: "kubernetes.rego",
	//			},
	//			{
	//				Name: "root_file_system_is_not_read-only",
	//			},
	//			{
	//				Name: "tag_latest_used",
	//			},
	//		},
	//	},
	//	{
	//		Name: "demo2-test",
	//		Scope: aquascope.Scope{
	//			Expression: "v1",
	//			Variables: []aquascope.Variable{
	//				{
	//					Attribute: "kubernetes.namespace",
	//					Value:     "kapns",
	//				},
	//			},
	//		},
	//		Controls: []conftest.KAPControl{
	//			{
	//				Name: "kubernetes.rego",
	//			},
	//			{
	//				Name: "manages_etchosts",
	//			},
	//			{
	//				Name: "root_file_system_is_not_read-only",
	//			},
	//			{
	//				Name: "image_tag_latest_used",
	//			},
	//		},
	//	},
	//}, policies)
}

func TestGetKubernetesScopeAttributes(t *testing.T) {
	attributes := conftest.GetKubernetesScopeAttributes(&appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ReplicaSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-549f5fcb58",
			Namespace: metav1.NamespaceDefault,
		},
	})
	assert.Equal(t, map[string]string{
		"kubernetes.namespace":  "default",
		"kubernetes.pod":        "nginx-549f5fcb58",
		"kubernetes.replicaset": "nginx-549f5fcb58",
	}, attributes)
}

func TestGetMatchedKAPolicies(t *testing.T) {
	inKubeSystemNamespacePolicy := conftest.KAPPolicy{
		Name: "in-kube-system-namespace",
		Scope: aquascope.Scope{
			//Expression: `{"expression":"v1","variables":[{"attribute":"kubernetes.namespace","value":"kapns"}]}`,
			Expression: "v1",
			Variables: []aquascope.Variable{
				{
					Attribute: "kubernetes.namespace",
					Value:     "kube-system",
				},
			},
		},
	}
	inAnyNamespacePolicy := conftest.KAPPolicy{
		Name: "in-any-namespace",
		Scope: aquascope.Scope{
			//Expression: `{"expression":"v1","variables":[{"attribute":"kubernetes.namespace","value":"kapns"}]}`,
			Expression: "v1",
			Variables: []aquascope.Variable{
				{
					Attribute: "kubernetes.namespace",
					Value:     "*",
				},
			},
		},
	}
	policies := []conftest.KAPPolicy{
		inKubeSystemNamespacePolicy,
		inAnyNamespacePolicy,
	}

	t.Run("A", func(t *testing.T) {
		matchedPolicies := conftest.GetMatchedKAPolicies(policies, &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-549f5fcb58",
				Namespace: metav1.NamespaceDefault,
				//Namespace: "kapns",
			},
		})
		assert.Equal(t, []conftest.KAPPolicy{inAnyNamespacePolicy}, matchedPolicies)
	})

	t.Run("B", func(t *testing.T) {
		matchedPolicies := conftest.GetMatchedKAPolicies(policies, &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-549f5fcb58",
				Namespace: "kube-system",
			},
		})
		assert.Equal(t, []conftest.KAPPolicy{inKubeSystemNamespacePolicy, inAnyNamespacePolicy}, matchedPolicies)
	})
}
