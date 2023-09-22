package universal

import (
	"context"
	"io/fs"

	"github.com/khulnasoft-lab/defsec/pkg/scan"
	"github.com/khulnasoft-lab/defsec/pkg/scanners/options"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/azure/arm"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/cloudformation"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/dockerfile"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/helm"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/json"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/kubernetes"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/terraform"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/toml"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/yaml"
)

type nestableFSScanners interface {
	scanners.FSScanner
	options.ConfigurableScanner
}

var _ scanners.FSScanner = (*Scanner)(nil)

type Scanner struct {
	fsScanners []nestableFSScanners
}

func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		fsScanners: []nestableFSScanners{
			terraform.New(opts...),
			cloudformation.New(opts...),
			dockerfile.NewScanner(opts...),
			kubernetes.NewScanner(opts...),
			json.NewScanner(opts...),
			yaml.NewScanner(opts...),
			toml.NewScanner(opts...),
			helm.New(opts...),
			arm.New(opts...),
		},
	}
	return s
}

func (s *Scanner) Name() string {
	return "Universal"
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error) {
	var results scan.Results
	for _, inner := range s.fsScanners {
		innerResults, err := inner.ScanFS(ctx, fs, dir)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}
