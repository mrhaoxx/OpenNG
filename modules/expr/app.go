package expr

import (
	ng "github.com/mrhaoxx/OpenNG"
)

func init() {
	ng.RegisterFunc("expr::http", NewHttpExpr)
	ng.RegisterFunc("expr::tcp", NewTCPExpr)
}
