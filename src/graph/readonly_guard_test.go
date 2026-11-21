package graph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadOnlyStaticGuard statically inspects all non-test Go source files in
// the Graph client (excluding OAuth token exchange in auth.go) and checks/
// packages to guarantee that no HTTP write methods (POST, PUT, PATCH, DELETE)
// are ever issued against Microsoft Graph.
func TestReadOnlyStaticGuard(t *testing.T) {
	forbiddenSelectors := map[string]bool{
		"MethodPost":   true,
		"MethodPut":    true,
		"MethodPatch":  true,
		"MethodDelete": true,
		"Post":         true,
		"PostForm":     true,
	}
	forbiddenStrings := map[string]bool{
		`"POST"`:   true,
		`"PUT"`:    true,
		`"PATCH"`:  true,
		`"DELETE"`: true,
	}

	dirs := []string{
		".",
		filepath.Join("..", "..", "checks"),
	}

	fset := token.NewFileSet()
	checked := 0

	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsNotExist(walkErr) {
					return nil
				}
				return walkErr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// OAuth 2.0 token and devicecode endpoints require HTTP POST per RFC 6749/8628.
			// All Microsoft Graph requests live outside auth.go.
			if filepath.Base(path) == "auth.go" {
				return nil
			}

			checked++
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}

			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.SelectorExpr:
					if ident, ok := node.X.(*ast.Ident); ok && ident.Name == "http" && forbiddenSelectors[node.Sel.Name] {
						pos := fset.Position(node.Pos())
						t.Errorf("read-only guard violation at %s: forbidden http.%s call in Graph/check code", pos, node.Sel.Name)
					}
				case *ast.BasicLit:
					if node.Kind == token.STRING && forbiddenStrings[node.Value] {
						pos := fset.Position(node.Pos())
						t.Errorf("read-only guard violation at %s: forbidden HTTP write verb literal %s", pos, node.Value)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	if checked == 0 {
		t.Fatal("read-only guard checked 0 source files")
	}
}
