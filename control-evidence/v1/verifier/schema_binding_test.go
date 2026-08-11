package verifier

import (
	"strings"
	"testing"
)

func TestSchemaBindingsFailClosedWhenRequiredBindingIsMissing(t *testing.T) {
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	schemas.requirement = nil
	err = validateSchemaBindings(schemas)
	if err == nil || !strings.Contains(err.Error(), "requirement") {
		t.Fatalf("validateSchemaBindings() error = %v, want missing requirement binding", err)
	}
}
