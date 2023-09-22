package documentdb

import (
	"github.com/khulnasoft-lab/defsec/pkg/providers/aws/documentdb"
	"github.com/khulnasoft-lab/vul-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) documentdb.DocumentDB {
	return documentdb.DocumentDB{
		Clusters: getClusters(cfFile),
	}
}
