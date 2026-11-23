// arm32_align_gate_test.go 实现 src/dpid/... 全仓零白名单 32 位 armeabi-v7a (GOARCH=arm)
// 64 位原子与共享内核缓冲区 8 字节对齐 AST + go/types 静态门禁单测。
package shm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// pureArm32Sizes 模拟无编译器隐式 align64 垫片特判的纯 32 位 ARM 内存布局(WordSize=4, MaxAlign=4),
// 用于强制要求结构体内的 64 位原子字段在物理定义顺序上就严格处于 offset % 8 == 0 位置。
type pureArm32Sizes struct{}

func (pureArm32Sizes) Alignof(T types.Type) int64 {
	switch t := T.Underlying().(type) {
	case *types.Array:
		return (pureArm32Sizes{}).Alignof(t.Elem())
	case *types.Struct:
		max := int64(1)
		for i := 0; i < t.NumFields(); i++ {
			if a := (pureArm32Sizes{}).Alignof(t.Field(i).Type()); a > max {
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
		sz := (pureArm32Sizes{}).Sizeof(T)
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

func (s pureArm32Sizes) Offsetsof(fields []*types.Var) []int64 {
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

func (s pureArm32Sizes) Sizeof(T types.Type) int64 {
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

type arm32PkgResolver struct {
	fset        *token.FileSet
	bctx        build.Context
	armSizes    types.Sizes
	dirByImport map[string]string
	cache       map[string]*types.Package
	inProgress  map[string]bool
	defImporter types.Importer
	srcImporter types.Importer
}

func newArm32PkgResolver(modRoot, modPrefix, goos string, sharedStdCache map[string]*types.Package) (*arm32PkgResolver, error) {
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
	// Walk module root to register all internal packages deterministically.
	_ = filepath.WalkDir(modRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := d.Name()
		if (strings.HasPrefix(name, ".") && path != modRoot) || strings.HasPrefix(name, "_") || name == "testdata" {
			return filepath.SkipDir
		}
		rel, rerr := filepath.Rel(modRoot, path)
		if rerr != nil {
			return nil
		}
		imp := modPrefix
		if rel != "." {
			imp = modPrefix + "/" + filepath.ToSlash(rel)
		}
		dirByImport[imp] = path
		return nil
	})

	// Query `go list` to resolve external module dependencies (if any) and stdlib dirs.
	cmd := exec.Command("go", "list", "-e", "-deps", "-f", "{{.ImportPath}}={{.Dir}}", "./...")
	cmd.Dir = modRoot
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm", "CGO_ENABLED=0")
	if out, err := cmd.Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			imp, dir, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && imp != "" && dir != "" {
				if _, exists := dirByImport[imp]; !exists {
					dirByImport[imp] = dir
				}
			}
		}
	}

	cache := make(map[string]*types.Package, len(sharedStdCache))
	for k, v := range sharedStdCache {
		cache[k] = v
	}
	return &arm32PkgResolver{
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

func (r *arm32PkgResolver) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	if pkg, ok := r.cache[path]; ok {
		return pkg, nil
	}
	// Standard library packages have no dot in the first path segment.
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
		return nil, fmt.Errorf("import dir %s (%s): %w", path, dir, err)
	}
	files, err := parseGoFileList(r.fset, dir, bp.GoFiles)
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

func parseGoFileList(fset *token.FileSet, dir string, names []string) ([]*ast.File, error) {
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

func isAtomic64Named(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	if named.Obj().Pkg().Path() != "sync/atomic" {
		return false
	}
	switch named.Obj().Name() {
	case "Int64", "Uint64":
		return true
	default:
		return false
	}
}

func typeContainsAtomic64(t types.Type, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	if isAtomic64Named(t) {
		return true
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Array:
		return u.Len() > 0 && typeContainsAtomic64(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if typeContainsAtomic64(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func typeContains64BitScalar(t types.Type, seen map[types.Type]bool) bool {
	t = types.Unalias(t)
	if isAtomic64Named(t) {
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
		return u.Len() > 0 && typeContains64BitScalar(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if typeContains64BitScalar(u.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}

var atomic64FuncSet = map[string]bool{
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

func stripParens(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func checkStructAtomic64Layout(
	fset *token.FileSet,
	pos token.Pos,
	prefix string,
	st *types.Struct,
	armSizes types.Sizes,
	pureSizes pureArm32Sizes,
	baseArmOff int64,
	basePureOff int64,
	visited map[*types.Struct]bool,
) []string {
	if st == nil || st.NumFields() == 0 {
		return nil
	}
	if visited[st] {
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
		if !typeContainsAtomic64(ft, map[types.Type]bool{}) {
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
		violations = append(violations, checkNestedAtomic64Type(fset, fPos, fieldPath, ft, armSizes, pureSizes, totalArm, totalPure, visited)...)
	}
	return violations
}

func checkNestedAtomic64Type(
	fset *token.FileSet,
	pos token.Pos,
	prefix string,
	t types.Type,
	armSizes types.Sizes,
	pureSizes pureArm32Sizes,
	baseArmOff int64,
	basePureOff int64,
	visited map[*types.Struct]bool,
) []string {
	var violations []string
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Array:
		if u.Len() > 1 && typeContainsAtomic64(u.Elem(), map[types.Type]bool{}) {
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
			violations = append(violations, checkNestedAtomic64Type(
				fset, pos, prefix+"[0]", u.Elem(), armSizes, pureSizes, baseArmOff, basePureOff, visited,
			)...)
		}
	case *types.Struct:
		if !isAtomic64Named(t) {
			violations = append(violations, checkStructAtomic64Layout(
				fset, pos, prefix, u, armSizes, pureSizes, baseArmOff, basePureOff, visited,
			)...)
		}
	}
	return violations
}

// selectorChainOffsetFromHeapOrRoot 计算 &x.a.b 在 32 位 ARM 下相对于根结构体(或最内层指针解引用结构体)的累计偏移。
func selectorChainOffsetFromHeapOrRoot(
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
	cur := stripParens(expr)
	for {
		switch n := cur.(type) {
		case *ast.SelectorExpr:
			sel, ok := info.Selections[n]
			if !ok || sel.Kind() != types.FieldVal {
				// Package-qualified identifier (e.g. pkg.GlobalVar).
				return 0, "", false, nil
			}
			steps = append(steps, step{
				sel:      sel,
				fieldStr: n.Sel.Name,
				pos:      n.Sel.Pos(),
			})
			// If Sel is indirect (through a pointer), that pointer allocation is the base struct root!
			if sel.Indirect() {
				cur = nil
			} else {
				cur = stripParens(n.X)
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
				cur = stripParens(n.X)
			} else {
				// Slice indexing starts from slice backing array pointer.
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

	// Reverse steps from outer base to leaf field.
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
					// Embedded pointer resets base offset to the pointed-to heap allocation.
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

func auditTypedPackageArm32(fset *token.FileSet, files []*ast.File, info *types.Info, armSizes types.Sizes) []string {
	var violations []string
	var pureSizes pureArm32Sizes
	checkedStructs := make(map[*types.Struct]bool)

	for _, af := range files {
		ast.Inspect(af, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.TypeSpec:
				if obj, ok := info.Defs[node.Name]; ok && obj != nil {
					t := obj.Type()
					if typeContainsAtomic64(t, map[types.Type]bool{}) {
						if st, ok := t.Underlying().(*types.Struct); ok {
							checkedStructs[st] = true
						}
						violations = append(violations, checkNestedAtomic64Type(
							fset, node.Pos(), node.Name.Name, t, armSizes, pureSizes, 0, 0, map[*types.Struct]bool{},
						)...)
					}
				}
			case *ast.StructType:
				if tv, ok := info.Types[node]; ok {
					if st, ok := tv.Type.Underlying().(*types.Struct); ok && !checkedStructs[st] {
						checkedStructs[st] = true
						if typeContainsAtomic64(st, map[types.Type]bool{}) {
							violations = append(violations, checkStructAtomic64Layout(
								fset, node.Pos(), "<anonymous_struct>", st, armSizes, pureSizes, 0, 0, map[*types.Struct]bool{},
							)...)
						}
					}
				}
			case *ast.ArrayType:
				if tv, ok := info.Types[node]; ok {
					if arr, ok := tv.Type.Underlying().(*types.Array); ok {
						violations = append(violations, checkNestedAtomic64Type(
							fset, node.Pos(), "<array>", arr, armSizes, pureSizes, 0, 0, map[*types.Struct]bool{},
						)...)
					}
				}
			case *ast.CallExpr:
				if len(node.Args) == 0 {
					return true
				}
				// Check 1: sync/atomic 64-bit functions taking &x.field.
				if sel, ok := stripParens(node.Fun).(*ast.SelectorExpr); ok {
					if obj := info.Uses[sel.Sel]; obj != nil && obj.Pkg() != nil &&
						obj.Pkg().Path() == "sync/atomic" && atomic64FuncSet[obj.Name()] {
						arg0 := stripParens(node.Args[0])
						if unary, ok := arg0.(*ast.UnaryExpr); ok && unary.Op == token.AND {
							off, chainDesc, isField, strideErrs := selectorChainOffsetFromHeapOrRoot(fset, unary.X, info, armSizes)
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

				// Check 2: unsafe.Pointer(&x.field) where field contains 64-bit integers/counters.
				if len(node.Args) == 1 {
					if tv, ok := info.Types[node.Fun]; ok && tv.IsType() {
						if basic, ok := tv.Type.Underlying().(*types.Basic); ok && basic.Kind() == types.UnsafePointer {
							arg0 := stripParens(node.Args[0])
							if unary, ok := arg0.(*ast.UnaryExpr); ok && unary.Op == token.AND {
								target := stripParens(unary.X)
								if _, isSel := target.(*ast.SelectorExpr); isSel {
									if targetTV, ok := info.Types[target]; ok && typeContains64BitScalar(targetTV.Type, map[types.Type]bool{}) {
										off, chainDesc, isField, strideErrs := selectorChainOffsetFromHeapOrRoot(fset, target, info, armSizes)
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

func runArm32ModuleAlignmentAudit(modRoot, modPrefix string, targetDirs []string) (int, []string, error) {
	var allViolations []string
	seenViolation := make(map[string]bool)
	checkedPackages := 0

	resolver, err := newArm32PkgResolver(modRoot, modPrefix, "linux", nil)
	if err != nil {
		return checkedPackages, nil, err
	}
	for _, dir := range targetDirs {
		bp, ierr := resolver.bctx.ImportDir(dir, 0)
		if ierr != nil {
			if _, noGo := ierr.(*build.NoGoError); noGo {
				continue
			}
			return checkedPackages, nil, fmt.Errorf("ImportDir(%s, GOOS=linux): %w", dir, ierr)
		}
		rel, rerr := filepath.Rel(modRoot, dir)
		if rerr != nil {
			return checkedPackages, nil, rerr
		}
		impPath := modPrefix
		if rel != "." {
			impPath = modPrefix + "/" + filepath.ToSlash(rel)
		}

		// Type-check package GoFiles + internal TestGoFiles together.
		var mainNames []string
		mainNames = append(mainNames, bp.GoFiles...)
		mainNames = append(mainNames, bp.TestGoFiles...)
		if len(mainNames) > 0 {
			files, perr := parseGoFileList(resolver.fset, dir, mainNames)
			if perr != nil {
				return checkedPackages, nil, perr
			}
			info := &types.Info{
				Types:      make(map[ast.Expr]types.TypeAndValue),
				Defs:       make(map[*ast.Ident]types.Object),
				Uses:       make(map[*ast.Ident]types.Object),
				Selections: make(map[*ast.SelectorExpr]*types.Selection),
			}
			conf := types.Config{
				Importer: resolver,
				Sizes:    resolver.armSizes,
			}
			pkg, cerr := conf.Check(impPath, resolver.fset, files, info)
			if cerr != nil {
				return checkedPackages, nil, fmt.Errorf("typecheck %s (GOOS=linux/arm): %w", impPath, cerr)
			}
			resolver.cache[impPath] = pkg
			checkedPackages++
			for _, v := range auditTypedPackageArm32(resolver.fset, files, info, resolver.armSizes) {
				if !seenViolation[v] {
					seenViolation[v] = true
					allViolations = append(allViolations, v)
				}
			}
		}

		// Type-check external XTestGoFiles (<pkg>_test), if any.
		if len(bp.XTestGoFiles) > 0 {
			xFiles, perr := parseGoFileList(resolver.fset, dir, bp.XTestGoFiles)
			if perr != nil {
				return checkedPackages, nil, perr
			}
			xInfo := &types.Info{
				Types:      make(map[ast.Expr]types.TypeAndValue),
				Defs:       make(map[*ast.Ident]types.Object),
				Uses:       make(map[*ast.Ident]types.Object),
				Selections: make(map[*ast.SelectorExpr]*types.Selection),
			}
			conf := types.Config{
				Importer: resolver,
				Sizes:    resolver.armSizes,
			}
			if _, cerr := conf.Check(impPath+"_test", resolver.fset, xFiles, xInfo); cerr != nil {
				return checkedPackages, nil, fmt.Errorf("typecheck %s_test: %w", impPath, cerr)
			}
			for _, v := range auditTypedPackageArm32(resolver.fset, xFiles, xInfo, resolver.armSizes) {
				if !seenViolation[v] {
					seenViolation[v] = true
					allViolations = append(allViolations, v)
				}
			}
		}
	}
	sort.Strings(allViolations)
	return checkedPackages, allViolations, nil
}

func TestArm32FullDpidRepoZeroWhitelistAlignmentGate(t *testing.T) {
	modRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve src/dpid root: %v", err)
	}
	var pkgDirs []string
	err = filepath.WalkDir(modRoot, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if (strings.HasPrefix(name, ".") && path != modRoot) || strings.HasPrefix(name, "_") || name == "testdata" {
			return filepath.SkipDir
		}
		entries, rerr := os.ReadDir(path)
		if rerr != nil {
			return rerr
		}
		for _, ent := range entries {
			if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".go") {
				pkgDirs = append(pkgDirs, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk src/dpid: %v", err)
	}
	sort.Strings(pkgDirs)
	if len(pkgDirs) < 20 {
		t.Fatalf("expected >= 20 packages under src/dpid, found only %d", len(pkgDirs))
	}

	checked, violations, err := runArm32ModuleAlignmentAudit(modRoot, "hnc.io/dpid", pkgDirs)
	if err != nil {
		t.Fatalf("32-bit arm alignment gate failed to analyze packages: %v", err)
	}
	if checked < 20 {
		t.Fatalf("expected >= 20 linux/arm packages typechecked, got %d", checked)
	}
	if len(violations) > 0 {
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "found %d 32-bit armeabi-v7a 64-bit alignment violations (zero whitelist):\n", len(violations))
		for _, v := range violations {
			fmt.Fprintf(&buf, "  - %s\n", v)
		}
		t.Fatal(buf.String())
	}
	t.Logf("arm32 alignment gate passed across %d packages under src/dpid (0 whitelist)", checked)
}

func TestArm32AlignmentGateCatchesSyntheticBugs(t *testing.T) {
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
	raw int64
	bpf struct {
		rx uint64
	}
}

func trigger(p *badRaw64Target) {
	atomic.AddInt64(&p.raw, 1)
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
		Importer: importer.ForCompiler(fset, "source", nil),
		Sizes:    armSizes,
	}
	if _, err := conf.Check("synthetic", fset, []*ast.File{af}, info); err != nil {
		t.Fatalf("typecheck synthetic: %v", err)
	}
	vs := auditTypedPackageArm32(fset, []*ast.File{af}, info, armSizes)
	joined := strings.Join(vs, "\n")
	for _, wantSub := range []string{
		"badAtomicStruct.cnt",
		"badNestedOuter.sub",
		"badArrayHolder.arr",
		"atomic.AddInt64(&raw)",
		"unsafe.Pointer(&bpf)",
	} {
		if !strings.Contains(joined, wantSub) {
			t.Fatalf("expected synthetic gate to catch %q, got:\n%s", wantSub, joined)
		}
	}
}
