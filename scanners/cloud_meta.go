package scanners

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// CloudMetaResult represents an exposed cloud credential, IMDS endpoint, or Kubernetes ServiceAccount token.
type CloudMetaResult struct {
	Provider      string `json:"provider"`
	Path          string `json:"path,omitempty"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	TokenSnippet  string `json:"token_snippet,omitempty"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

// ScanCloudAndContainerMetadata audits Kubernetes service accounts, cloud credential stores, and accessible IMDS endpoints.
func ScanCloudAndContainerMetadata() ([]CloudMetaResult, error) {
	var results []CloudMetaResult

	// 1. Kubernetes In-Cluster ServiceAccount Token
	k8sTokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if data, err := os.ReadFile(k8sTokenPath); err == nil && len(data) > 0 {
		tokenStr := strings.TrimSpace(string(data))
		snippet := tokenStr
		if len(snippet) > 30 {
			snippet = snippet[:30] + "..."
		}
		results = append(results, CloudMetaResult{
			Provider:      "Kubernetes",
			Path:          k8sTokenPath,
			RiskLevel:     "CRITICAL",
			Reason:        "Kubernetes in-cluster ServiceAccount token is mounted and readable — permits cluster API interaction via kubectl or curl",
			TokenSnippet:  snippet,
			ExploitHint:   fmt.Sprintf("curl -k -H 'Authorization: Bearer %s' https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/default/pods", snippet),
			Remediation:   "Set 'automountServiceAccountToken: false' in pod spec if cluster API access is not required",
			ComplianceTag: "CIS-K8s-5.1.6 / NIST-AC-6",
			IsDangerous:   true,
		})
	}

	// 2. Kubernetes Admin / Cluster Configurations
	k8sConfigs := []string{
		"/etc/kubernetes/admin.conf",
		"/etc/kubernetes/kubelet.conf",
		"/etc/kubernetes/controller-manager.conf",
		"/etc/kubernetes/scheduler.conf",
	}
	for _, p := range k8sConfigs {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			results = append(results, CloudMetaResult{
				Provider:      "Kubernetes",
				Path:          p,
				RiskLevel:     "CRITICAL",
				Reason:        fmt.Sprintf("Privileged Kubernetes cluster configuration file '%s' is readable", p),
				ExploitHint:   fmt.Sprintf("export KUBECONFIG=%s && kubectl auth can-i --list", p),
				Remediation:   fmt.Sprintf("chmod 0600 %s && chown root:root %s", p, p),
				ComplianceTag: "CIS-K8s-1.1.1 / NIST-AC-6",
				IsDangerous:   true,
			})
		}
	}

	// 3. Cloud Provider Metadata Service (IMDS) Check (Fail-fast non-blocking 200ms timeout)
	checkIMDSEndpoints(&results)

	return results, nil
}

func checkIMDSEndpoints(results *[]CloudMetaResult) {
	client := &http.Client{
		Timeout: 200 * time.Millisecond,
	}

	// AWS IMDSv1 Check
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				roleName := strings.TrimSpace(string(body))
				if roleName != "" {
					*results = append(*results, CloudMetaResult{
						Provider:      "AWS",
						RiskLevel:     "CRITICAL",
						Reason:        fmt.Sprintf("AWS IMDSv1 is accessible without authentication. IAM Role exposed: %s", roleName),
						ExploitHint:   fmt.Sprintf("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", roleName),
						Remediation:   "Enforce AWS IMDSv2 (Session token required) with hop limit = 1",
						ComplianceTag: "CIS-AWS-1.16 / NIST-SC-28",
						IsDangerous:   true,
					})
				}
			}
		}
	}

	// GCP IMDS Check
	ctxGCP, cancelGCP := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelGCP()
	reqGCP, err := http.NewRequestWithContext(ctxGCP, "GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err == nil {
		reqGCP.Header.Set("Metadata-Flavor", "Google")
		respGCP, err := client.Do(reqGCP)
		if err == nil {
			defer respGCP.Body.Close()
			if respGCP.StatusCode == 200 {
				*results = append(*results, CloudMetaResult{
					Provider:      "GCP",
					RiskLevel:     "CRITICAL",
					Reason:        "GCP Compute Engine Metadata service is accessible. Default Service Account token exposed.",
					ExploitHint:   "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
					Remediation:   "Enforce Workload Identity and disable legacy instance metadata endpoints",
					ComplianceTag: "CIS-GCP-1.12 / NIST-SC-28",
					IsDangerous:   true,
				})
			}
		}
	}
}
