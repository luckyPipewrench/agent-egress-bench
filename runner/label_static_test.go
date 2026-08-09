package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// labelSelectorError is deliberately structural: field selectors and raw JSON
// keys are both rejected, so a future scorer cannot evade the boundary by
// switching from typed fields to map access.
func labelSelectorError(filename, source string, selectors map[string]bool) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, source, 0)
	if err != nil {
		return err
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil || !selectors[function.Name.Name] {
			continue
		}
		var found error
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if found != nil {
				return false
			}
			switch value := node.(type) {
			case *ast.SelectorExpr:
				if value.Sel.Name == "Claims" || value.Sel.Name == "CapabilityTags" {
					found = fmt.Errorf("%s reads %s at %s", function.Name.Name, value.Sel.Name, fset.Position(value.Pos()))
				}
			case *ast.BasicLit:
				if value.Kind == token.STRING && (value.Value == `"claims"` || value.Value == `"capability_tags"`) {
					found = fmt.Errorf("%s reads label JSON key at %s", function.Name.Name, fset.Position(value.Pos()))
				}
			}
			return found == nil
		})
		if found != nil {
			return found
		}
	}
	return nil
}

func TestLabelBoundaryStaticGate(t *testing.T) {
	// Reporting readers are intentionally omitted. Every selected function makes
	// scope, state, score, measurement-validity, or receipt membership decisions.
	files := map[string]map[string]bool{
		"main.go":                {"runCases": true},
		"result_state.go":        {"resultStateFor": true, "caseResultForState": true},
		"score.go":               {"scoreCase": true, "scoreCaseWithEvidence": true, "computeScores": true, "computeFullCorpusScores": true, "computeCategoryScores": true, "measurementStatus": true},
		"summary.go":             {"countErrors": true},
		"receipt_profile.go":     {"buildReceiptProfile": true, "observeReceipts": true},
		"receipt_observation.go": {"observeReceipts": true},
	}
	for path, selectors := range files {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) && path == "receipt_observation.go" {
					return
				}
				t.Fatal(err)
			}
			if err := labelSelectorError(filepath.Base(path), string(data), selectors); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLabelBoundaryRejectsSelector(t *testing.T) {
	source := `package test
func checkApplicability(profile Profile) bool { return len(profile.Claims) > 0 }
`
	err := labelSelectorError("synthetic.go", source, map[string]bool{"checkApplicability": true})
	if err == nil || !strings.Contains(err.Error(), "Claims") {
		t.Fatalf("label selector gate error = %v, want Claims rejection", err)
	}
}
