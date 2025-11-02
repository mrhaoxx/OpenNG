package config

const DescHostnameFormat = "supported hostname format:\nexample.com\na.example.com\n*.example.com\n*"

var refs_assertions = map[string]Assert{
	"_": {
		Type: "map",
		Sub: AssertMap{
			"Services": {
				Desc: "service functions which will be called at startup",
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {Type: "string", Default: "_"},
							"kind": {Type: "string", Required: true},
							"spec": {Type: "any"},
						},
					},
				},
			},
			"version": {
				Desc:     "config version",
				Type:     "int",
				Required: true,
				Forced:   true,
				Default:  6,
			},
			"Config": {
				Desc: "global configurations",
				Type: "map",
				Sub: AssertMap{
					"Logger": {
						Type: "map",
						Sub: AssertMap{
							"TimeZone": {
								Desc:         "time zone for logger",
								Type:         "string",
								Default:      "Local",
								Enum:         []any{"Local", "UTC", "Asia/Shanghai"},
								AllowNonEnum: true,
							},
							"Verbose": {
								Desc:    "verbose level",
								Type:    "bool",
								Default: false,
							},
							"EnableSSELogger": {
								Desc:    "enable server sent event logger for webui",
								Type:    "bool",
								Default: false,
							},
							"EnableConsoleLogger": {
								Desc:    "enable console logger",
								Type:    "bool",
								Default: true,
							},
							"FileLogger": {
								Type: "map",
								Sub: AssertMap{
									"Path": {
										Type:     "string",
										Required: true,
									},
								},
							},
							"UDPLogger": {
								Type: "map",
								Sub: AssertMap{
									"Addr": {
										Type:     "string",
										Required: true,
									},
								},
							},
						},
					},
				},
			},
		},
	},
}

var refs = map[string]Inst{}

func Register(name string, inst Inst, assert Assert) {
	refs[name] = inst
	refs_assertions[name] = assert
}
