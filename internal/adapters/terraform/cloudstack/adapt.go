package cloudstack

import (
	"github.com/aquasecurity/defsec/pkg/providers/cloudstack"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/khulnasoft-lab/vul-iac/internal/adapters/terraform/cloudstack/compute"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
