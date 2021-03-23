package starboard_operator

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

const (
	assertionTimeout = 3 * time.Minute
)

var _ = Describe("Starboard Operator", func() {

	const (
		namespaceName  = corev1.NamespaceDefault
		deploymentName = "wordpress"
	)

	Describe("When unmanaged Pod is created", func() {

		ctx := context.Background()
		var pod *corev1.Pod

		BeforeEach(func() {
			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unmanaged-nginx",
					Namespace: corev1.NamespaceDefault,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			}
			err := kubeClient.Create(ctx, pod)
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should create VulnerabilityReport and ConfigAuditReport", func() {
			Eventually(HasConfigAuditReportOwnedBy(pod), assertionTimeout).Should(BeTrue())
			Eventually(HasVulnerabilityReportOwnedBy(pod), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClient.Delete(ctx, pod)
			Expect(err).ToNot(HaveOccurred())
		})

	})

	Describe("When Deployment is created", func() {

		ctx := context.Background()

		BeforeEach(func() {
			_, err := kubeClientset.AppsV1().Deployments(namespaceName).
				Create(ctx, &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      deploymentName,
						Namespace: namespaceName,
					},
					Spec: appsv1.DeploymentSpec{
						Replicas: pointer.Int32Ptr(1),
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "wordpress",
							},
						},
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: labels.Set{
									"app": "wordpress",
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:  "wordpress",
										Image: "wordpress:4.9",
									},
								},
							},
						},
					},
				}, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			Eventually(HasActiveReplicaSet(namespaceName, deploymentName), assertionTimeout).Should(BeTrue())
		})

		It("Should create VulnerabilityReport and ConfigAuditReport", func() {
			rs, err := GetActiveReplicaSetForDeployment(namespaceName, deploymentName)
			Expect(err).ToNot(HaveOccurred())
			Expect(rs).ToNot(BeNil())

			Eventually(HasConfigAuditReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
			Eventually(HasVulnerabilityReportOwnedBy(rs), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClientset.AppsV1().Deployments(namespaceName).
				Delete(ctx, deploymentName, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	// TODO Add a scenario for rolling update, i.e. create Deployment and then update its container image.

	Describe("When CronJob is created", func() {
		var cronJob *batchv1beta1.CronJob

		BeforeEach(func() {
			cronJob = &batchv1beta1.CronJob{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: namespaceName,
					Name:      "hello",
				},
				Spec: batchv1beta1.CronJobSpec{
					Schedule: "*/1 * * * *",
					JobTemplate: batchv1beta1.JobTemplateSpec{
						Spec: batchv1.JobSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									RestartPolicy: corev1.RestartPolicyOnFailure,
									Containers: []corev1.Container{
										{
											Name:  "hello",
											Image: "busybox",
											Command: []string{
												"/bin/sh",
												"-c",
												"date; echo Hello from the Kubernetes cluster",
											},
										},
									},
								},
							},
						},
					},
				},
			}
			err := kubeClient.Create(context.Background(), cronJob)
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should create VulnerabilityReport and ConfigAuditReport", func() {
			Eventually(HasConfigAuditReportOwnedBy(cronJob), assertionTimeout).Should(BeTrue())
			// FIXME(issue: #415): Assign VulnerabilityReports to CronJob instead of Jobs. The PodSpec of a CronJob does not change so there's no point in rescanning individual Jobs.
			// Eventually(HasVulnerabilityReportOwnedBy(cronJob), assertionTimeout).Should(BeTrue())
		})

		AfterEach(func() {
			err := kubeClient.Delete(context.Background(), cronJob)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Describe("When operator is started", func() {

		It("Should scan all nodes with CIS Kubernetes Benchmark checks", func() {
			nodeList, err := kubeClientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			Expect(err).ToNot(HaveOccurred())
			for _, node := range nodeList.Items {
				Eventually(HasCISKubeBenchReportFor(node), assertionTimeout).Should(BeTrue())
			}
		})

	})
})

func HasActiveReplicaSet(namespace, name string) func() bool {
	return func() bool {
		rs, err := GetActiveReplicaSetForDeployment(namespace, name)
		if err != nil {
			return false
		}
		return rs != nil
	}
}

func HasVulnerabilityReportOwnedBy(obj client.Object) func() bool {
	return func() bool {
		gvk, err := apiutil.GVKForObject(obj, scheme)
		if err != nil {
			// TODO Report error
			return false
		}
		var reportList v1alpha1.VulnerabilityReportList
		err = kubeClient.List(context.Background(), &reportList, client.MatchingLabels{
			kube.LabelResourceKind:      gvk.Kind,
			kube.LabelResourceName:      obj.GetName(),
			kube.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			// TODO Report error
			return false
		}
		return len(reportList.Items) == 1
	}
}

func HasConfigAuditReportOwnedBy(obj client.Object) func() bool {
	return func() bool {
		gvk, err := apiutil.GVKForObject(obj, scheme)
		if err != nil {
			// TODO Report error
			return false
		}
		var reportsList v1alpha1.ConfigAuditReportList
		err = kubeClient.List(context.Background(), &reportsList, client.MatchingLabels{
			kube.LabelResourceKind:      gvk.Kind,
			kube.LabelResourceName:      obj.GetName(),
			kube.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			// TODO Report error
			return false
		}
		return len(reportsList.Items) == 1
	}
}

func GetActiveReplicaSetForDeployment(namespace, name string) (*appsv1.ReplicaSet, error) {
	deployment, err := kubeClientset.AppsV1().Deployments(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	deploymentSelector, err := metav1.LabelSelectorAsMap(deployment.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("mapping label selector: %w", err)
	}
	selector := labels.Set(deploymentSelector)

	replicaSetList, err := kubeClientset.AppsV1().ReplicaSets(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, err
	}

	for _, replicaSet := range replicaSetList.Items {
		if deployment.Annotations["deployment.kubernetes.io/revision"] !=
			replicaSet.Annotations["deployment.kubernetes.io/revision"] {
			continue
		}
		return replicaSet.DeepCopy(), nil
	}
	return nil, nil
}

func HasCISKubeBenchReportFor(node corev1.Node) func() bool {
	return func() bool {
		report, err := kubeBenchReportReader.FindByOwner(context.Background(), kube.Object{Kind: kube.KindNode, Name: node.Name})
		if err != nil {
			return false
		}
		return report != nil
	}
}
