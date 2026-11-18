package facts

import (
	"go/ast"
	"go/token"
)

// Complexity holds one function's cyclomatic and cognitive complexity.
type Complexity struct {
	Cyclomatic int
	Cognitive  int
	Statements int
}

// ComputeComplexity measures a function body. Cyclomatic counts branch points
// (if, for, range, case, &&, ||, ??-like selectors); cognitive adds a nesting
// penalty like the Cognitive Complexity metric.
func ComputeComplexity(fset *token.FileSet, node *ast.FuncDecl) Complexity {
	c := &cyc{cyclomatic: 1}
	if node.Body != nil {
		c.walkBlock(node.Body)
	}
	return Complexity{Cyclomatic: c.cyclomatic, Cognitive: c.cognitive, Statements: c.statements}
}

type cyc struct {
	cyclomatic int
	cognitive  int
	statements int
	nesting    int
}

func (c *cyc) walkBlock(b *ast.BlockStmt) {
	if b == nil {
		return
	}
	for _, s := range b.List {
		c.walkStmt(s)
	}
}

func (c *cyc) walkIf(x *ast.IfStmt, isElseIf bool) {
	c.walkStmt(x.Init)
	c.walkExpr(x.Cond)
	c.cyclomatic++
	if !isElseIf {
		c.cognitive += 1 + c.nesting
	} else {
		c.cognitive += 1
	}
	c.nesting++
	if x.Body != nil {
		for _, s := range x.Body.List {
			c.walkStmt(s)
		}
	}
	c.nesting--
	if x.Else != nil {
		if elseIf, ok := x.Else.(*ast.IfStmt); ok {
			c.walkIf(elseIf, true)
		} else {
			c.cognitive += 1
			c.nesting++
			c.walkStmt(x.Else)
			c.nesting--
		}
	}
}

func (c *cyc) walkStmt(stmt ast.Stmt) {
	if stmt == nil {
		return
	}
	switch s := stmt.(type) {
	case *ast.BlockStmt:
		c.walkBlock(s)
	case *ast.DeclStmt:
		c.statements++
		if gd, ok := s.Decl.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, val := range vs.Values {
						c.walkExpr(val)
					}
				}
			}
		}
	case *ast.EmptyStmt:
		// no-op
	case *ast.LabeledStmt:
		c.walkStmt(s.Stmt)
	case *ast.ExprStmt:
		c.statements++
		c.walkExpr(s.X)
	case *ast.SendStmt:
		c.statements++
		c.walkExpr(s.Chan)
		c.walkExpr(s.Value)
	case *ast.IncDecStmt:
		c.walkExpr(s.X)
	case *ast.AssignStmt:
		c.statements++
		for _, lhs := range s.Lhs {
			c.walkExpr(lhs)
		}
		for _, rhs := range s.Rhs {
			c.walkExpr(rhs)
		}
	case *ast.GoStmt:
		c.statements++
		c.walkExpr(s.Call)
	case *ast.DeferStmt:
		c.statements++
		c.walkExpr(s.Call)
	case *ast.ReturnStmt:
		c.statements++
		for _, res := range s.Results {
			c.walkExpr(res)
		}
	case *ast.BranchStmt:
		if s.Label != nil {
			c.cognitive += 1 + c.nesting
		}
	case *ast.IfStmt:
		c.walkIf(s, false)
	case *ast.ForStmt:
		c.cyclomatic++
		c.cognitive += 1 + c.nesting
		c.walkStmt(s.Init)
		c.walkExpr(s.Cond)
		c.walkStmt(s.Post)
		c.nesting++
		c.walkBlock(s.Body)
		c.nesting--
	case *ast.RangeStmt:
		c.cyclomatic++
		c.cognitive += 1 + c.nesting
		c.walkExpr(s.Key)
		c.walkExpr(s.Value)
		c.walkExpr(s.X)
		c.nesting++
		c.walkBlock(s.Body)
		c.nesting--
	case *ast.SwitchStmt:
		c.cyclomatic++
		c.cognitive += 1 + c.nesting
		c.walkStmt(s.Init)
		c.walkExpr(s.Tag)
		c.nesting++
		c.walkBlock(s.Body)
		c.nesting--
	case *ast.TypeSwitchStmt:
		c.cyclomatic++
		c.cognitive += 1 + c.nesting
		c.walkStmt(s.Init)
		c.walkStmt(s.Assign)
		c.nesting++
		c.walkBlock(s.Body)
		c.nesting--
	case *ast.CaseClause:
		if len(s.List) > 0 {
			c.cyclomatic++
			c.cognitive += 1
		}
		for _, expr := range s.List {
			c.walkExpr(expr)
		}
		for _, bodyStmt := range s.Body {
			c.walkStmt(bodyStmt)
		}
	case *ast.SelectStmt:
		c.cyclomatic++
		c.cognitive += 1 + c.nesting
		c.nesting++
		c.walkBlock(s.Body)
		c.nesting--
	case *ast.CommClause:
		if s.Comm != nil {
			c.cyclomatic++
			c.cognitive += 1
		}
		c.walkStmt(s.Comm)
		for _, bodyStmt := range s.Body {
			c.walkStmt(bodyStmt)
		}
	}
}

func (c *cyc) walkExpr(expr ast.Expr) {
	if expr == nil {
		return
	}
	switch x := expr.(type) {
	case *ast.BinaryExpr:
		if x.Op == token.LAND || x.Op == token.LOR {
			c.cyclomatic++
			c.cognitive += 1 + c.nesting
		}
		c.walkExpr(x.X)
		c.walkExpr(x.Y)
	case *ast.UnaryExpr:
		c.walkExpr(x.X)
	case *ast.ParenExpr:
		c.walkExpr(x.X)
	case *ast.SelectorExpr:
		c.walkExpr(x.X)
	case *ast.IndexExpr:
		c.walkExpr(x.X)
		c.walkExpr(x.Index)
	case *ast.IndexListExpr:
		c.walkExpr(x.X)
		for _, idx := range x.Indices {
			c.walkExpr(idx)
		}
	case *ast.SliceExpr:
		c.walkExpr(x.X)
		c.walkExpr(x.Low)
		c.walkExpr(x.High)
		c.walkExpr(x.Max)
	case *ast.TypeAssertExpr:
		c.walkExpr(x.X)
		c.walkExpr(x.Type)
	case *ast.CallExpr:
		c.walkExpr(x.Fun)
		for _, arg := range x.Args {
			c.walkExpr(arg)
		}
	case *ast.StarExpr:
		c.walkExpr(x.X)
	case *ast.CompositeLit:
		c.walkExpr(x.Type)
		for _, elt := range x.Elts {
			c.walkExpr(elt)
		}
	case *ast.KeyValueExpr:
		c.walkExpr(x.Key)
		c.walkExpr(x.Value)
	case *ast.FuncLit:
		c.nesting++
		c.walkBlock(x.Body)
		c.nesting--
	case *ast.ArrayType:
		c.walkExpr(x.Len)
		c.walkExpr(x.Elt)
	case *ast.MapType:
		c.walkExpr(x.Key)
		c.walkExpr(x.Value)
	case *ast.ChanType:
		c.walkExpr(x.Value)
	case *ast.Ellipsis:
		c.walkExpr(x.Elt)
	}
}
