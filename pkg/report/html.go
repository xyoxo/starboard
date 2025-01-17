package report

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/configauditreport"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/kubebench"
	"github.com/aquasecurity/starboard/pkg/report/templates"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type workloadReporter struct {
	clock                      ext.Clock
	vulnerabilityReportsReader vulnerabilityreport.ReadWriter
	configAuditReportsReader   configauditreport.ReadWriter
}

func NewWorkloadReporter(clock ext.Clock, client client.Client) WorkloadReporter {
	return &workloadReporter{
		clock:                      clock,
		vulnerabilityReportsReader: vulnerabilityreport.NewReadWriter(client),
		configAuditReportsReader:   configauditreport.NewReadWriter(client),
	}
}

func (h *workloadReporter) RetrieveData(workload kube.Object) (templates.WorkloadReport, error) {
	ctx := context.Background()
	configAuditReport, err := h.configAuditReportsReader.FindByOwnerInHierarchy(ctx, workload)
	if err != nil {
		return templates.WorkloadReport{}, err
	}
	vulnerabilityReports, err := h.vulnerabilityReportsReader.FindByOwnerInHierarchy(ctx, workload)
	if err != nil {
		return templates.WorkloadReport{}, err
	}

	vulnsReports := map[string]v1alpha1.VulnerabilityScanResult{}
	for _, vulnerabilityReport := range vulnerabilityReports {
		containerName, ok := vulnerabilityReport.Labels[kube.LabelContainerName]
		if !ok {
			continue
		}

		sort.Stable(vulnerabilityreport.BySeverity{Vulnerabilities: vulnerabilityReport.Report.Vulnerabilities})

		vulnsReports[containerName] = vulnerabilityReport.Report
	}
	if configAuditReport == nil && len(vulnsReports) == 0 {
		return templates.WorkloadReport{}, fmt.Errorf("no configaudits or vulnerabilities found for workload %s/%s/%s",
			workload.Namespace, workload.Kind, workload.Name)
	}
	return templates.WorkloadReport{
		Workload:          workload,
		GeneratedAt:       h.clock.Now(),
		VulnsReports:      vulnsReports,
		ConfigAuditReport: configAuditReport,
	}, nil
}

func (h *workloadReporter) Generate(workload kube.Object, writer io.Writer) error {
	data, err := h.RetrieveData(workload)
	if err != nil {
		return err
	}

	templates.WritePageTemplate(writer, &data)
	return nil
}

type namespaceReporter struct {
	clock  ext.Clock
	client client.Client
}

func NewNamespaceReporter(clock ext.Clock, client client.Client) NamespaceReporter {
	return &namespaceReporter{
		clock:  clock,
		client: client,
	}
}

func (r *namespaceReporter) RetrieveData(namespace kube.Object) (templates.NamespaceReport, error) {
	var vulnerabilityReportList v1alpha1.VulnerabilityReportList
	err := r.client.List(context.Background(), &vulnerabilityReportList, client.InNamespace(namespace.Name))
	if err != nil {
		return templates.NamespaceReport{}, err
	}

	return templates.NamespaceReport{
		Namespace:            namespace,
		GeneratedAt:          r.clock.Now(),
		Top5VulnerableImages: r.topNImagesBySeverityCount(vulnerabilityReportList.Items, 5),
	}, nil
}

func (r *namespaceReporter) topNImagesBySeverityCount(reports []v1alpha1.VulnerabilityReport, N int) []v1alpha1.VulnerabilityReport {
	b := append(reports[:0:0], reports...)

	vulnerabilityreport.OrderedBy(vulnerabilityreport.SummaryCount...).
		SortDesc(b)

	return b[:ext.MinInt(N, len(b))]
}

func (r *namespaceReporter) Generate(namespace kube.Object, out io.Writer) error {
	data, err := r.RetrieveData(namespace)
	if err != nil {
		return err
	}
	templates.WritePageTemplate(out, &data)
	return nil
}

type nodeReporter struct {
	clock                  ext.Clock
	client                 client.Client
	kubebenchReportsReader kubebench.ReadWriter
}

// NewNodeReporter generate the html reporter
func NewNodeReporter(clock ext.Clock, client client.Client) NodeReporter {
	return &nodeReporter{
		clock:                  clock,
		client:                 client,
		kubebenchReportsReader: kubebench.NewReadWriter(client),
	}
}

func (r *nodeReporter) Generate(node kube.Object, out io.Writer) error {
	data, err := r.RetrieveData(node)
	if err != nil {
		return err
	}
	templates.WritePageTemplate(out, &data)
	return nil
}

func (r *nodeReporter) RetrieveData(node kube.Object) (templates.NodeReport, error) {
	found := &v1alpha1.CISKubeBenchReport{}
	err := r.client.Get(context.Background(), types.NamespacedName{Name: node.Name}, found)
	if err != nil {
		return templates.NodeReport{}, err
	}

	return templates.NodeReport{
		GeneratedAt:        r.clock.Now(),
		Node:               node,
		CisKubeBenchReport: found,
	}, nil
}
