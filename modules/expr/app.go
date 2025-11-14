package expr

import (
	ng "github.com/mrhaoxx/OpenNG"
	ngexpr "github.com/mrhaoxx/OpenNG/pkg/expr"
)

func init() {
	ng.RegisterFunc("expr::http", ngexpr.NewHttpExpr)
	ng.RegisterFunc("expr::tcp", ngexpr.NewTCPExpr)
}
