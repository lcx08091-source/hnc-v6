// arm32_align_gate_test.go 实现 daemon/hnc_httpd 零白名单 32 位 armeabi-v7a (GOARCH=arm)
// 64 位原子与内核共享结构体 8 字节对齐 AST + go/types 门禁单测, 以及热升级 shm 无感回退与 ART 环境透传回归测试。
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/shm"
)

type httpdPureArm32Sizes struct{}

func (httpdPureArm32Sizes) Alignof(T types.Type) int64 {
	switch t := T.Underlying().(type) {
	case *types.Array:
		return (httpdPureArm32Sizes{}).Alignof(t.Elem())
	case *types.Struct:
		max := int64(1)
		for i := 0; i < t.NumFields(); i++ {
			if a := (httpdPureArm32Sizes{}).Alignof(t.Field(i).Type()); a > max {
				max = a
			}
		}
		return max
	case *types.Slice, *types.Interface:
		return 4
	case *types.Basic:
		if t.Info()&types.IsString != 0 {
			return 4
		}
		sz := (httpdPureArm32Sizes{}).Sizeof(T)
		if sz < 1 {
			return 1
		}
		if t.Info()&types.IsComplex != 0 {
			sz /= 2
		}
		if sz > 4 {
			return 4
		}
		return sz
	default:
		return 4
	}
}

func (s httpdPureArm32Sizes) Offsetsof(fields []*types.Var) []int64 {
	offsets := make([]int64, len(fields))
	var cur int64
	for i, f := range fields {
		a := s.Alignof(f.Type())
		if a > 1 && cur%a != 0 {
			cur += a - (cur % a)
		}
		offsets[i] = cur
		cur += s.Sizeof(f.Type())
	}
	return offsets
}

func (s httpdPureArm32Sizes) Sizeof(T types.Type) int64 {
	switch t := T.Underlying().(type) {
	case *types.Basic:
		switch t.Kind() {
		case types.Bool, types.Int8, types.Uint8:
			return 1
		case types.Int16, types.Uint16:
			return 2
		case types.Int32, types.Uint32, types.Float32, types.Int, types.Uint, types.Uintptr, types.UnsafePointer:
			return 4
		case types.Int64, types.Uint64, types.Float64, types.Complex64:
			return 8
		case types.Complex128:
			return 16
		case types.String:
			return 8
		default:
			return 4
		}
	case *types.Array:
		n := t.Len()
		if n <= 0 {
			return 0
		}
		esz := s.Sizeof(t.Elem())
		a := s.Alignof(t.Elem())
		stride := esz
		if a > 1 && stride%a != 0 {
			stride += a - (stride % a)
		}
		return stride*(n-1) + esz
	case *types.Slice:
		return 12
	case *types.Interface:
		return 8
	case *types.Struct:
		n := t.NumFields()
		if n == 0 {
			return 0
		}
		fields := make([]*types.Var, n)
		for i := 0; i < n; i++ {
			fields[i] = t.Field(i)
		}
		offs := s.Offsetsof(fields)
		sz := offs[n-1] + s.Sizeof(fields[n-1].Type())
		a := s.Alignof(t)
		if a > 1 && sz%a != 0 {
			sz += a - (sz % a)
		}
		return sz
	default:
		return 4
	}
}

type httpdArm32Importer struct {
	fset        *token.FileSet
	bctx        build.Context
	armSizes    types.Sizes
	dirByImport map[string]string
	cache       map[string]*types.Package
	inProgress  map[string]bool
	defImporter types.Importer
	srcImporter types.Importer
}

func newHttpdArm32Importer(pkgDir, goos string, sharedStdCache map[string]*types.Package) (*httpdArm32Importer, error) {
	armSizes := types.SizesFor("gc", "arm")
	if armSizes == nil {
		return nil, fmt.Errorf("types.SizesFor(gc, arm) returned nil")
	}
	fset := token.NewFileSet()
	bctx := build.Default
	bctx.GOOS = goos
	bctx.GOARCH = "arm"
	bctx.Compiler = "gc"
	bctx.CgoEnabled = false

	dirByImport := make(map[string]string)
	dpidRoot := filepath.Clean(filepath.Join(pkgDir, "..", "..", "src", "dpid"))
	dirByImport["hnc.io/dpid/shm"] = filepath.Join(dpidRoot, "shm")

	cmd := exec.Command("go", "list", "-e", "-deps", "-f", "{{.ImportPath}}={{.Dir}}", ".")
	cmd.Dir = pkgDir
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm", "CGO_ENABLED=0")
	if out, err := cmd.Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			imp, dir, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && imp != "" && dir != "" {
				dirByImport[imp] = dir
			}
		}
	}

	cache := make(map[string]*types.Package, len(sharedStdCache))
	for k, v := range sharedStdCache {
		cache[k] = v
	}
	return &httpdArm32Importer{
		fset:        fset,
		bctx:        bctx,
		armSizes:    armSizes,
		dirByImport: dirByImport,
		cache:       cache,
		inProgress:  make(map[string]bool),
		defImporter: importer.Default(),
		srcImporter: importer.ForCompiler(fset, "source", nil),
	}, nil
}

func (r *httpdArm32Importer) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	if pkg, ok := r.cache[path]; ok {
		return pkg, nil
	}
	firstSeg, _, _ := strings.Cut(path, "/")
	if !strings.Contains(firstSeg, ".") {
		pkg, err := r.defImporter.Import(path)
		if err != nil {
			pkg, err = r.srcImporter.Import(path)
		}
		if err == nil {
			r.cache[path] = pkg
		}
		return pkg, err
	}

	dir, ok := r.dirByImport[path]
	if !ok {
		return r.srcImporter.Import(path)
	}
	if r.inProgress[path] {
		return nil, fmt.Errorf("import cycle on %s", path)
	}
	r.inProgress[path] = true
	defer delete(r.inProgress, path)

	bp, err := r.bctx.ImportDir(dir, 0)
	if err != nil {
		return nil, fmt.Errorf("import dependency %s (%s): %w", path, dir, err)
	}
	files, err := httpdParseGoFiles(r.fset, dir, bp.GoFiles)
	if err != nil {
		return nil, err
	}
	conf := types.Config{
		Importer: r,
		Sizes:    r.armSizes,
	}
	pkg, err := conf.Check(path, r.fset, files, nil)
	if err != nil {
		return nil, fmt.Errorf("typecheck dependency %s: %w", path, err)
	}
	r.cache[path] = pkg
	return pkg, nil
}

func httpdParseGoFiles(fset *token.FileSet, dir string, names []string) ([]*ast.File, error) {
	out := make([]*ast.File, 0, len(names))
	for _, name := range names {
		full := filepath.Join(dir, name)
		af, err := parser.ParseFile(fset, full, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", full, err)
		}
		out = append(out, af)
	}
	return out, nil
}

func httpdIsAtomic64Named(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	if named.Obj().Pkg().Path() != "sync/atomic" {
		return false
	}
	return named.Obj().Name() == "Int64" || named.Obj().Name() == "Uint64"
}

func httpdContainsAtomic64(t types.Type, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	if httpdIsAtomic64Named(t) {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Array:
		return u.Len() > 0 && httpdContainsAtomic64(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if httpdContainsAtomic64(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func httpdContains64BitScalar(t types.Type, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	if httpdIsAtomic64Named(t) {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.Int64 || u.Kind() == types.Uint64
	case *types.Array:
		return u.Len() > 0 && httpdContains64BitScalar(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if httpdContains64BitScalar(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

var httpdAtomic64Funcs = map[string]bool{
	"LoadInt64":            true,
	"StoreInt64":           true,
	"AddInt64":             true,
	"SwapInt64":            true,
	"CompareAndSwapInt64":  true,
	"AndInt64":             true,
	"OrInt64":              true,
	"LoadUint64":           true,
	"StoreUint64":          true,
	"AddUint64":            true,
	"SwapUint64":           true,
	"CompareAndSwapUint64": true,
	"AndUint64":            true,
	"OrUint64":             true,
}

func httpdStripParens(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func httpdCheckStructAtomic64(
	fset *token.FileSet,
	pos token.Pos,
	prefix string,
	st *types.Struct,
	armSizes types.Sizes,
	pureSizes httpdPureArm32Sizes,
	baseArmOff int64,
	basePureOff int64,
	visited map[*types.Struct]bool,
) []string {
	if st == nil || st.NumFields() == 0 || visited[st] {
		return nil
	}
	visited[st] = true
	defer delete(visited, st)

	fields := make([]*types.Var, st.NumFields())
	for i := 0; i < st.NumFields(); i++ {
		fields[i] = st.Field(i)
	}
	armOffs := armSizes.Offsetsof(fields)
	pureOffs := pureSizes.Offsetsof(fields)

	var violations []string
	for i, f := range fields {
		ft := f.Type()
		if !httpdContainsAtomic64(ft, map[types.Type]bool{}) {
			continue
		}
		fieldPath := prefix + "." + f.Name()
		fPos := f.Pos()
		if !fPos.IsValid() {
			fPos = pos
		}
		totalArm := baseArmOff + armOffs[i]
		totalPure := basePureOff + pureOffs[i]
		if totalArm%8 != 0 || totalPure%8 != 0 {
			violations = append(violations, fmt.Sprintf(
				"%s: %s contains 64-bit atomic at 32-bit ARM offset=%d (rawOrderOffset=%d), want offset%%8==0",
				fset.Position(fPos), fieldPath, totalArm, totalPure,
			))
		}
		violations = append(violations, httpdCheckNestedAtomic64(
			fset, fPos, fieldPath, ft, armSizes, pureSizes, totalArm, totalPure, visited,
		)...)
	}
	return violations
}

func httpdCheckNestedAtomic64(
	fset *token.FileSet,
	pos token.Pos,
	prefix string,
	t types.Type,
	armSizes types.Sizes,
	pureSizes httpdPureArm32Sizes,
	baseArmOff int64,
	basePureOff int64,
	visited map[*types.Struct]bool,
) []string {
	var violations []string
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Array:
		if u.Len() > 1 && httpdContainsAtomic64(u.Elem(), map[types.Type]bool{}) {
			elemArmSz := armSizes.Sizeof(u.Elem())
			elemPureSz := pureSizes.Sizeof(u.Elem())
			if elemArmSz%8 != 0 || elemPureSz%8 != 0 {
				violations = append(violations, fmt.Sprintf(
					"%s: %s array element sizeof=%d (rawSize=%d) with 64-bit atomic violates sizeof%%8==0 on 32-bit ARM",
					fset.Position(pos), prefix, elemArmSz, elemPureSz,
				))
			}
		}
		if u.Len() > 0 {
			violations = append(violations, httpdCheckNestedAtomic64(
				fset, pos, prefix+"[0]", u.Elem(), armSizes, pureSizes, baseArmOff, basePureOff, visited,
			)...)
		}
	case *types.Struct:
		if !httpdIsAtomic64Named(t) {
			violations = append(violations, httpdCheckStructAtomic64(
				fset, pos, prefix, u, armSizes, pureSizes, baseArmOff, basePureOff, visited,
			)...)
		}
	}
	return violations
}

func httpdSelectorChainOffset(
	fset *token.FileSet,
	expr ast.Expr,
	info *types.Info,
	armSizes types.Sizes,
) (totalOff int64, desc string, isStructField bool, strideViolations []string) {
	type step struct {
		sel      *types.Selection
		fieldStr string
		arrElem  types.Type
		pos      token.Pos
	}
	var steps []step
	cur := httpdStripParens(expr)
	for {
		switch n := cur.(type) {
		case *ast.SelectorExpr:
			sel, ok := info.Selections[n]
			if !ok || sel.Kind() != types.FieldVal {
				return 0, "", false, nil
			}
			steps = append(steps, step{
				sel:      sel,
				fieldStr: n.Sel.Name,
				pos:      n.Sel.Pos(),
			})
			if sel.Indirect() {
				cur = nil
			} else {
				cur = httpdStripParens(n.X)
			}
		case *ast.IndexExpr:
			tv, ok := info.Types[n.X]
			if !ok {
				cur = nil
				continue
			}
			if arr, isArr := tv.Type.Underlying().(*types.Array); isArr {
				steps = append(steps, step{
					arrElem:  arr.Elem(),
					fieldStr: "[i]",
					pos:      n.Lbrack,
				})
				cur = httpdStripParens(n.X)
			} else {
				cur = nil
			}
		default:
			cur = nil
		}
		if cur == nil {
			break
		}
	}
	if len(steps) == 0 {
		return 0, "", false, nil
	}

	var names []string
	for i := len(steps) - 1; i >= 0; i-- {
		st := steps[i]
		names = append(names, st.fieldStr)
		if st.arrElem != nil {
			esz := armSizes.Sizeof(st.arrElem)
			if esz%8 != 0 {
				strideViolations = append(strideViolations, fmt.Sprintf(
					"%s: indexed array element %s sizeof=%d violates sizeof%%8==0 for 64-bit address-taken field on 32-bit ARM",
					fset.Position(st.pos), st.arrElem.String(), esz,
				))
			}
			continue
		}
		if st.sel != nil {
			recvType := st.sel.Recv()
			if ptr, ok := recvType.Underlying().(*types.Pointer); ok {
				recvType = ptr.Elem()
			}
			curStruct, ok := recvType.Underlying().(*types.Struct)
			if !ok {
				continue
			}
			for _, idx := range st.sel.Index() {
				fields := make([]*types.Var, curStruct.NumFields())
				for fi := 0; fi < curStruct.NumFields(); fi++ {
					fields[fi] = curStruct.Field(fi)
				}
				offs := armSizes.Offsetsof(fields)
				totalOff += offs[idx]
				nextT := fields[idx].Type()
				if ptr, ok := nextT.Underlying().(*types.Pointer); ok {
					totalOff = 0
					nextT = ptr.Elem()
				}
				curStruct, _ = nextT.Underlying().(*types.Struct)
				if curStruct == nil {
					break
				}
			}
			isStructField = true
		}
	}
	return totalOff, strings.Join(names, "."), isStructField, strideViolations
}

func auditHttpdFilesArm32(fset *token.FileSet, files []*ast.File, info *types.Info, armSizes types.Sizes) []string {
	var violations []string
	var pureSizes httpdPureArm32Sizes
	checkedStructs := make(map[*types.Struct]bool)

	for _, af := range files {
		ast.Inspect(af, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.TypeSpec:
				if obj, ok := info.Defs[node.Name]; ok && obj != nil {
					t := obj.Type()
					if httpdContainsAtomic64(t, map[types.Type]bool{}) {
						if st, ok := t.Underlying().(*types.Struct); ok {
							checkedStructs[st] = true
						}
						violations = append(violations, httpdCheckNestedAtomic64(
							fset, node.Pos(), node.Name.Name, t, armSizes, pureSizes, 0, 0, map[*types.Struct]bool{},
						)...)
					}
				}
			case *ast.StructType:
				if tv, ok := info.Types[node]; ok {
					if st, ok := tv.Type.Underlying().(*types.Struct); ok && !checkedStructs[st] {
						checkedStructs[st] = true
						if httpdContainsAtomic64(st, map[types.Type]bool{}) {
							violations = append(violations, httpdCheckStructAtomic64(
								fset, node.Pos(), "<anonymous_struct>", st, armSizes, pureSizes, 0, 0, map[*types.Struct]bool{},
							)...)
						}
					}
				}
			case *ast.ArrayType:
				if tv, ok := info.Types[node]; ok {
					if arr, ok := tv.Type.Underlying().(*types.Array); ok {
						violations = append(violations, httpdCheckNestedAtomic64(
							fset, node.Pos(), "<array>", arr, armSizes, pureSizes, 0, 0, map[*types.Struct]bool{},
						)...)
					}
				}
			case *ast.CallExpr:
				if len(node.Args) == 0 {
					return true
				}
				if sel, ok := httpdStripParens(node.Fun).(*ast.SelectorExpr); ok {
					if obj := info.Uses[sel.Sel]; obj != nil && obj.Pkg() != nil &&
						obj.Pkg().Path() == "sync/atomic" && httpdAtomic64Funcs[obj.Name()] {
						arg0 := httpdStripParens(node.Args[0])
						if unary, ok := arg0.(*ast.UnaryExpr); ok && unary.Op == token.AND {
							off, chainDesc, isField, strideErrs := httpdSelectorChainOffset(fset, unary.X, info, armSizes)
							violations = append(violations, strideErrs...)
							if isField && off%8 != 0 {
								violations = append(violations, fmt.Sprintf(
									"%s: atomic.%s(&%s) targets 32-bit ARM unaligned struct offset=%d (want offset%%8==0)",
									fset.Position(node.Pos()), obj.Name(), chainDesc, off,
								))
							}
						}
					}
				}
				if len(node.Args) == 1 {
					if tv, ok := info.Types[node.Fun]; ok && tv.IsType() {
						if basic, ok := tv.Type.Underlying().(*types.Basic); ok && basic.Kind() == types.UnsafePointer {
							arg0 := httpdStripParens(node.Args[0])
							if unary, ok := arg0.(*ast.UnaryExpr); ok && unary.Op == token.AND {
								target := httpdStripParens(unary.X)
								if _, isSel := target.(*ast.SelectorExpr); isSel {
									if targetTV, ok := info.Types[target]; ok && httpdContains64BitScalar(targetTV.Type, map[types.Type]bool{}) {
										off, chainDesc, isField, strideErrs := httpdSelectorChainOffset(fset, target, info, armSizes)
										violations = append(violations, strideErrs...)
										if isField && off%8 != 0 {
											violations = append(violations, fmt.Sprintf(
												"%s: unsafe.Pointer(&%s) targets 64-bit struct field at unaligned 32-bit ARM offset=%d (want offset%%8==0)",
												fset.Position(node.Pos()), chainDesc, off,
											))
										}
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	return violations
}

func TestArm32HttpdPackageZeroWhitelistAlignmentGate(t *testing.T) {
	pkgDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	imp, err := newHttpdArm32Importer(pkgDir, "linux", nil)
	if err != nil {
		t.Fatalf("newHttpdArm32Importer(linux): %v", err)
	}
	bp, err := imp.bctx.ImportDir(pkgDir, 0)
	if err != nil {
		t.Fatalf("ImportDir(linux): %v", err)
	}
	var names []string
	names = append(names, bp.GoFiles...)
	names = append(names, bp.TestGoFiles...)
	files, err := httpdParseGoFiles(imp.fset, pkgDir, names)
	if err != nil {
		t.Fatalf("parse files (linux): %v", err)
	}
	checkedFiles := len(files)
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	conf := types.Config{
		Importer: imp,
		Sizes:    imp.armSizes,
	}
	if _, err := conf.Check("hnc_httpd", imp.fset, files, info); err != nil {
		t.Fatalf("typecheck hnc_httpd (GOOS=linux/arm): %v", err)
	}
	allViolations := auditHttpdFilesArm32(imp.fset, files, info, imp.armSizes)

	if checkedFiles < 40 {
		t.Fatalf("expected >= 40 files typechecked in daemon/hnc_httpd, got %d", checkedFiles)
	}
	sort.Strings(allViolations)
	if len(allViolations) > 0 {
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "found %d 32-bit armeabi-v7a 64-bit alignment violations in daemon/hnc_httpd (zero whitelist):\n", len(allViolations))
		for _, v := range allViolations {
			fmt.Fprintf(&buf, "  - %s\n", v)
		}
		t.Fatal(buf.String())
	}
	t.Logf("arm32 alignment gate passed across %d Go files in daemon/hnc_httpd (0 whitelist)", checkedFiles)
}

func TestArm32HttpdAlignmentGateCatchesSyntheticBugs(t *testing.T) {
	src := `package synthetic

import (
	"sync/atomic"
	"unsafe"
)

type badAtomicStruct struct {
	flag uint32
	cnt  atomic.Uint64
}

type badNestedOuter struct {
	head bool
	sub  struct {
		x atomic.Int64
	}
}

type badArrayElem struct {
	cnt  atomic.Uint64
	tail uint32
}

type badArrayHolder struct {
	arr [2]badArrayElem
}

type badRaw64Target struct {
	fd  int
	raw uint64
	bpf struct {
		tx uint64
	}
}

func trigger(p *badRaw64Target) {
	atomic.StoreUint64(&p.raw, 9)
	_ = unsafe.Pointer(&p.bpf)
}
`
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	armSizes := types.SizesFor("gc", "arm")
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	conf := types.Config{
		Importer: importer.Default(),
		Sizes:    armSizes,
	}
	if _, err := conf.Check("synthetic", fset, []*ast.File{af}, info); err != nil {
		t.Fatalf("typecheck synthetic: %v", err)
	}
	vs := auditHttpdFilesArm32(fset, []*ast.File{af}, info, armSizes)
	joined := strings.Join(vs, "\n")
	for _, wantSub := range []string{
		"badAtomicStruct.cnt",
		"badNestedOuter.sub",
		"badArrayHolder.arr",
		"atomic.StoreUint64(&raw)",
		"unsafe.Pointer(&bpf)",
	} {
		if !strings.Contains(joined, wantSub) {
			t.Fatalf("expected synthetic gate to catch %q, got:\n%s", wantSub, joined)
		}
	}
}

func TestCoreHubHotUpgradeSilentShmFallbackAndArtEnvWhitelist(t *testing.T) {
	srv, dir := setupTestV6Server(t)
	hub := srv.CoreHub()
	defer hub.Close()

	runDir := filepath.Join(dir, "run")
	shmPath := shm.FilePath(runDir)

	// Seed dpi_state.json with an active client not yet persisted in devices.json.
	nowUnix := time.Now().Unix()
	dpiJSON := fmt.Sprintf(`{"clients":{"c1":{"client_mac":"aa:bb:cc:00:00:77","client_ip":"192.168.43.77","last_seen":%d}}}`, nowUnix)
	if err := os.WriteFile(filepath.Join(runDir, "dpi_state.json"), []byte(dpiJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Build a valid v2 image as template, then mutate into hot-upgrade transient states.
	tmpShm := filepath.Join(t.TempDir(), shm.DefaultFileName)
	tw, err := shm.OpenWriterPath(tmpShm, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = tw.Write(shm.MonotonicNs(), 5, 1, nil)
	_ = tw.Close()
	validImg, err := os.ReadFile(tmpShm)
	if err != nil {
		t.Fatal(err)
	}

	v1Img := append([]byte(nil), validImg...)
	binary.LittleEndian.PutUint32(v1Img[8:12], 1) // simulate old RC3 Version=1

	badMagicImg := append([]byte(nil), validImg...)
	copy(badMagicImg[0:8], "BADMAGIC")

	shortImg := validImg[:128]

	beforeFallbacks := hub.shmFallbackCount.Load()
	cases := []struct {
		name       string
		payload    []byte
		wantReason string
	}{
		{"schema_v1", v1Img, "schema_mismatch"},
		{"short_region", shortImg, "short_region"},
		{"bad_magic", badMagicImg, "bad_magic"},
	}
	for i, tc := range cases {
		if err := os.WriteFile(shmPath, tc.payload, 0o644); err != nil {
			t.Fatal(err)
		}
		snap := hub.RefreshSnapshotNow()
		if !snap.Healthy {
			t.Fatalf("%s: expected Healthy=true during hot upgrade fallback", tc.name)
		}
		if errs := hub.DpiShmBulkhead.totalErrors.Load(); errs != 0 {
			t.Fatalf("%s: expected DpiShmBulkhead.totalErrors == 0, got %d", tc.name, errs)
		}
		if st := hub.DpiShmBulkhead.CircuitState(); st != "closed" {
			t.Fatalf("%s: expected circuit closed, got %q", tc.name, st)
		}
		ext := snap.Extensions["dpi_shm_vector"].(map[string]any)
		if ext["source"] != "json_fallback" || ext["fallback_reason"] != tc.wantReason {
			t.Fatalf("%s: unexpected ext=%+v", tc.name, ext)
		}
		// Verify json_fallback merged both devices.json (.20) and dpi_state.json (.77) -> 2 online clients.
		if snap.Live.Online != 2 {
			t.Fatalf("%s: expected 2 online devices from devices.json + dpi_state.json fallback, got %d", tc.name, snap.Live.Online)
		}
		if hub.shmFallbackCount.Load() < beforeFallbacks+uint64(i+1) {
			t.Fatalf("%s: expected shmFallbackCount incremented", tc.name)
		}
	}

	// Once upgraded v2 shm_vector.bin is published, CoreHub recovers cleanly and clears diagnostic LastError.
	if err := os.WriteFile(shmPath, validImg, 0o644); err != nil {
		t.Fatal(err)
	}
	recovered := hub.RefreshSnapshotNow()
	rExt := recovered.Extensions["dpi_shm_vector"].(map[string]any)
	if rExt["source"] != "shm_seqlock" || recovered.Bulkheads["dpi_shm"].LastError != "" {
		t.Fatalf("expected clean recovery to shm_seqlock with empty LastError, ext=%+v bh=%+v", rExt, recovered.Bulkheads["dpi_shm"])
	}

	// Verify hubSanitizedAndroidEnv & ExecIsolatedAndroidCmd preserve ART classpaths while stripping untrusted vars.
	t.Setenv("BOOTCLASSPATH", "/apex/com.android.art/javalib/core-oj.jar")
	t.Setenv("SYSTEMSERVERCLASSPATH", "/system/framework/services.jar")
	t.Setenv("ANDROID_ROOT", "/system")
	t.Setenv("ANDROID_DATA", "/data")
	t.Setenv("TZ", "Asia/Shanghai")
	t.Setenv("UNTRUSTED_INJECTED_SECRET", "should_not_leak")

	out, err := ExecIsolatedAndroidCmd(context.Background(), 2*time.Second, "sh", "-c",
		`printf "%s|%s|%s|%s" "$BOOTCLASSPATH" "$SYSTEMSERVERCLASSPATH" "$ANDROID_ROOT" "$UNTRUSTED_INJECTED_SECRET"`)
	if err != nil {
		t.Fatalf("ExecIsolatedAndroidCmd env probe failed: %v", err)
	}
	wantEnvOut := "/apex/com.android.art/javalib/core-oj.jar|/system/framework/services.jar|/system|"
	if string(out) != wantEnvOut {
		t.Fatalf("unexpected child env: got %q want %q", string(out), wantEnvOut)
	}
}
