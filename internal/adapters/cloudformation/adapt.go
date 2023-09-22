package cloudformation

import (
	"github.com/khulnasoft-lab/defsec/pkg/state"
	"github.com/khulnasoft-lab/vul-iac/internal/adapters/cloudformation/aws"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
