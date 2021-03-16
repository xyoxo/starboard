package starboard

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PluginContext interface {
	GetConfigMapByName(name string) (*corev1.ConfigMap, error)
}

type pluginContext struct {
	client    client.Client
	namespace string
}

func NewPluginContext(namespace string, client client.Client) PluginContext {
	return &pluginContext{
		namespace: namespace,
		client:    client,
	}
}

func (pc *pluginContext) GetConfigMapByName(name string) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	err := pc.client.Get(context.Background(), types.NamespacedName{
		Namespace: pc.namespace,
		Name:      name,
	}, cm)
	return cm, err
}
