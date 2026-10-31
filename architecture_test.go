// Copyright 2021-2026 ALTESSA SOLUTIONS INC.
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package proteus_test

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const modulePath = "github.com/altessa-s/go-proteus"

type layerRule struct {
	internal []string
	external []string
}

// layers defines the allowed internal and external imports for every package in go-proteus.
var layers = map[string]layerRule{
	".": {
		internal: []string{"sdk"},
	},
	"sdk": {},
	"signature": {
		internal: []string{"."},
	},
	"host": {
		internal: []string{".", "sdk"},
	},
	"spi": {
		internal: []string{".", "sdk"},
	},
	"dirsource": {
		internal: []string{"."},
		external: []string{"github.com/altessa-s/go-atlas-core/"},
	},
	"goloader": {
		internal: []string{"."},
		external: []string{"github.com/altessa-s/go-atlas-core/"},
	},
	"watch": {
		internal: []string{"."},
		external: []string{
			"github.com/altessa-s/go-atlas-core/",
			"github.com/fsnotify/fsnotify",
		},
	},
	"signing": {
		internal: []string{".", "signature"},
		external: []string{
			"github.com/altessa-s/go-atlas-core/",
			"github.com/altessa-s/go-tlsutils",
		},
	},
	"proteustest": {
		internal: []string{".", "sdk", "signature", "signing"},
		external: []string{
			"github.com/altessa-s/go-atlas-core/",
			"github.com/stretchr/testify",
		},
	},
	"internal/testplugins/good":            {internal: []string{"sdk"}},
	"internal/testplugins/init_panics":     {internal: []string{"sdk"}},
	"internal/testplugins/init_blocks":     {internal: []string{"sdk"}},
	"internal/testplugins/bad_descriptor":  {internal: []string{"sdk"}},
	"internal/testplugins/name_mismatch":   {internal: []string{"sdk"}},
	"internal/testplugins/spi_v1":          {internal: []string{"sdk"}},
	"internal/testplugins/spi_v2":          {internal: []string{"sdk"}},
	"internal/testplugins/pkg_init_panics": {internal: []string{"sdk"}},
	"cmd/proteus": {
		internal: []string{".", "sdk", "signature", "signing", "dirsource"},
		external: []string{
			"github.com/altessa-s/go-atlas-core/",
			"github.com/spf13/cobra",
		},
	},
}

type goListPkg struct {
	ImportPath   string
	Name         string
	Dir          string
	Imports      []string
	TestImports  []string
	XTestImports []string
	GoFiles      []string
}

func listPackages(t *testing.T) []goListPkg {
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "./...")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []goListPkg
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p goListPkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode go list: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func relPkgPath(importPath string) string {
	if importPath == modulePath {
		return "."
	}
	return strings.TrimPrefix(importPath, modulePath+"/")
}

func TestPackageLayers(t *testing.T) {
	t.Parallel()
	pkgs := listPackages(t)
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages")
	}

	for _, p := range pkgs {
		rel := relPkgPath(p.ImportPath)
		rule, ok := layers[rel]
		if !ok {
			t.Errorf("package %q is not registered in architecture_test.go layers table", rel)
			continue
		}

		for _, imp := range p.Imports {
			if imp == modulePath || strings.HasPrefix(imp, modulePath+"/") {
				target := relPkgPath(imp)
				if !slices.Contains(rule.internal, target) {
					t.Errorf("package %q imports internal package %q (allowed: %v)", rel, target, rule.internal)
				}
				continue
			}
			if isThirdParty(imp) && !matchesPrefix(imp, rule.external) {
				t.Errorf("package %q imports disallowed external package %q (allowed: %v)", rel, imp, rule.external)
			}
		}
	}
}

func TestSpecialImportIsolation(t *testing.T) {
	t.Parallel()
	pkgs := listPackages(t)

	for _, p := range pkgs {
		rel := relPkgPath(p.ImportPath)
		allImports := slices.Concat(p.Imports, p.TestImports, p.XTestImports)

		for _, imp := range allImports {
			if imp == "plugin" && rel != "goloader" {
				t.Errorf("package %q imports stdlib \"plugin\"; only \"goloader\" may import it", rel)
			}
			if imp == "os/exec" && rel != "proteustest" && rel != "." {
				t.Errorf("package %q imports \"os/exec\"; only \"proteustest\" (and architecture_test) may import it", rel)
			}
			if imp == "syscall" || strings.HasPrefix(imp, "golang.org/x/sys") {
				t.Errorf("package %q imports banned package %q (process hardening belongs at service startup)", rel, imp)
			}
		}
	}
}

func TestMonolithImportDenied(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "bin" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			return nil
		}
		for _, imp := range file.Imports {
			val := strings.Trim(imp.Path.Value, `"`)
			if val == "github.com/altessa-s/go-atlas" || strings.HasPrefix(val, "github.com/altessa-s/go-atlas/") {
				t.Errorf("%s imports banned monolith package %q", path, val)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
}

func TestGoModPurity(t *testing.T) {
	t.Parallel()
	banned := []string{
		"github.com/altessa-s/go-atlas ",
		"github.com/altessa-s/go-atlas\n",
		"google.golang.org/grpc",
		"google.golang.org/protobuf",
		"gopkg.in/yaml",
		"golang.org/x/sys",
		"replace ",
	}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "devtools" || d.Name() == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			return nil
		}
		text := string(data)
		for _, b := range banned {
			if strings.Contains(text, b) {
				t.Errorf("%s contains banned directive or dependency %q", path, strings.TrimSpace(b))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk go.mod: %v", err)
	}
}

func TestASTConventions(t *testing.T) {
	t.Parallel()
	pkgs := listPackages(t)
	fset := token.NewFileSet()

	for _, p := range pkgs {
		rel := relPkgPath(p.ImportPath)
		isTestPlugin := strings.HasPrefix(rel, "internal/testplugins/")

		for _, goFile := range p.GoFiles {
			if strings.HasSuffix(goFile, "_test.go") {
				continue
			}
			fullPath := filepath.Join(p.Dir, goFile)
			parsed, err := parser.ParseFile(fset, fullPath, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", fullPath, err)
			}
			isGen := strings.HasSuffix(goFile, "_gen.go")

			for _, decl := range parsed.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					if d.Recv == nil && d.Name.Name == "init" {
						// Only internal/testplugins/pkg_init_panics is allowed to define init() to test Defect 1.
						if rel != "internal/testplugins/pkg_init_panics" {
							t.Errorf("%s defines forbidden init() function", fullPath)
						}
					}
					if !isGen && d.Recv == nil && strings.HasPrefix(d.Name.Name, "With") {
						t.Errorf("%s defines hand-written option %s (must be generated by optgen in options_gen.go)", fullPath, d.Name.Name)
					}
				case *ast.GenDecl:
					if d.Tok != token.VAR || isGen || isTestPlugin {
						continue
					}
					for _, spec := range d.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for _, ident := range vs.Names {
							if ident.IsExported() && !strings.HasPrefix(ident.Name, "Err") {
								t.Errorf("%s declares exported mutable variable %q (only Err* sentinels allowed)", fullPath, ident.Name)
							}
						}
					}
				}
			}
		}
	}
}

func TestPackageDocs(t *testing.T) {
	t.Parallel()
	pkgs := listPackages(t)

	for _, p := range pkgs {
		rel := relPkgPath(p.ImportPath)
		for _, required := range []string{"doc.go", "README.md"} {
			target := filepath.Join(p.Dir, required)
			if _, err := os.Stat(target); err != nil {
				t.Errorf("package %q is missing %s", rel, required)
			}
		}
	}
}

func isThirdParty(imp string) bool {
	first, _, ok := strings.Cut(imp, "/")
	return ok && strings.Contains(first, ".")
}

func matchesPrefix(imp string, allowed []string) bool {
	for _, prefix := range allowed {
		if imp == prefix || strings.HasPrefix(imp, prefix) {
			return true
		}
	}
	return false
}
