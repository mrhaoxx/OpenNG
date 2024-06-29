package ui

var _builtin_refs_assertions = map[string]Assert{
	"_": {
		Type: "list",
		Sub: AssertMap{
			"name": {Type: "string", Required: true},
			"ref":  {Type: "string", Required: true},
			"args": {Type: "map"},
		},
	},
	"builtin::http::proxier": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"hosts": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {
								Type:     "string",
								Required: true,
							},
							"hosts": {
								Type:     "list",
								Required: true,
								Sub: AssertMap{
									"_": {Type: "string"},
								},
							},
							"backend": {
								Type:     "string",
								Required: true,
							},
							"MaxConnsPerHost": {
								Type:    "int",
								Default: 0,
							},
							"TlsSkipVerify": {
								Type:    "bool",
								Default: false,
							},
						},
					},
				},
			},
			"allowhosts": {
				Type:    "list",
				Default: []string{"*"},
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
		},
	},
}
