package starboard_operator

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/operator"
	"github.com/aquasecurity/starboard/pkg/operator/etc"
	"github.com/aquasecurity/starboard/pkg/starboard"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	buildInfo = starboard.BuildInfo{Version: "dev", Commit: "none", Date: "unknown"}
)

var (
	testEnv *envtest.Environment
)

var (
	scheme        *runtime.Scheme
	kubeClientset kubernetes.Interface
	kubeClient    client.Client
)

var (
	kubeBenchReportReader kubebench.Reader
)

func TestStarboardOperator(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Starboard Operator")
}

var _ = BeforeSuite(func(done Done) {
	operatorConfig, err := etc.GetOperatorConfig()
	Expect(err).ToNot(HaveOccurred())

	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	kubeConfig, err := ctrl.GetConfig()
	Expect(err).ToNot(HaveOccurred())

	kubeClientset, err = kubernetes.NewForConfig(kubeConfig)
	Expect(err).ToNot(HaveOccurred())

	scheme = starboard.NewScheme()
	kubeClient, err = client.New(kubeConfig, client.Options{Scheme: scheme})
	Expect(err).ToNot(HaveOccurred())

	kubeBenchReportReader = kubebench.NewReadWriter(kubeClient)

	testEnv = &envtest.Environment{
		UseExistingCluster: pointer.BoolPtr(true),
		Config:             kubeConfig,
		CRDDirectoryPaths:  []string{filepath.Join("..", "..", "deploy", "crd")},
	}

	_, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()

		err = operator.Run(buildInfo, operatorConfig)
		Expect(err).ToNot(HaveOccurred())
	}()

	close(done)
}, 60)

var _ = AfterSuite(func() {
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})
