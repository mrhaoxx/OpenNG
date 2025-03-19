package ui

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/mrhaoxx/OpenNG/auth"
	authbackends "github.com/mrhaoxx/OpenNG/auth/backend"
	"github.com/mrhaoxx/OpenNG/dns"
	"github.com/mrhaoxx/OpenNG/http"
	"github.com/mrhaoxx/OpenNG/log"
	"github.com/mrhaoxx/OpenNG/ssh"
	"github.com/mrhaoxx/OpenNG/tcp"
	"github.com/mrhaoxx/OpenNG/tls"
	"github.com/mrhaoxx/OpenNG/utils"
	"github.com/mrhaoxx/OpenNG/wireguard"
	gossh "golang.org/x/crypto/ssh"
)

const DescHostnameFormat = "supported hostname format:\nexample.com\na.example.com\n*.example.com\n*"

var _builtin_refs_assertions = map[string]Assert{
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
				Default:  5,
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
	"builtin::http::reverseproxier": {
		Type:     "map",
		Required: true,
		Desc:     "HTTP reverse proxy configuration",
		Sub: AssertMap{
			"hosts": {
				Type: "list",
				Desc: "reverse proxy host configurations",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {
								Type:     "string",
								Required: true,
								Desc:     "name of the proxy configuration",
							},
							"hosts": {
								Type:     "list",
								Required: true,
								Desc:     "hostnames to match for this proxy",
								Sub: AssertMap{
									"_": {Type: "string", Desc: DescHostnameFormat},
								},
							},
							"backend": {
								Type:     "string",
								Required: true,
								Desc:     "backend URL to proxy requests to",
							},
							"MaxConnsPerHost": {
								Type:    "int",
								Default: 0,
								Desc:    "maximum concurrent connections per backend host",
							},
							"TlsSkipVerify": {
								Type:    "bool",
								Default: false,
								Desc:    "skip TLS certificate verification for backend",
							},
						},
					},
				},
			},
			"allowhosts": {
				Type:    "list",
				Default: []*ArgNode{{Type: "string", Value: "*"}},
				Desc:    "hostnames that this proxy will handle",
				Sub: AssertMap{
					"_": {Type: "string", Desc: DescHostnameFormat},
				},
			},
		},
	},
	"builtin::tls": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"certificates": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"CertFile": {
								Type:     "string",
								Desc:     "path to certificate file",
								Required: true,
							},
							"KeyFile": {
								Type:     "string",
								Desc:     "path to key file",
								Required: true,
							},
						},
					},
				},
			},
		},
	},
	"builtin::http::midware": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"services": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {
								Type:     "string",
								Required: true,
							},
							"logi": {
								Type:     "ptr",
								Desc:     "pointer to service function",
								Required: true,
							},
							"hosts": {
								Type: "list",
								Desc: "hostnames this service handles",
								Sub: AssertMap{
									"_": {Type: "string", Desc: DescHostnameFormat},
								},
							},
						},
					},
				},
			},
			"cgis": {
				Type:    "list",
				Default: []*ArgNode{},
				Desc:    "CGI handlers for /ng-cgi/* paths",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"logi": {
								Type:     "ptr",
								Required: true,
								Desc:     "pointer to CGI handler implementation",
							},
							"paths": {
								Type: "list",
								Desc: "URL paths this CGI handles",
								Sub: AssertMap{
									"_": {Type: "string"},
								},
							},
						},
					},
				},
			},
			"forward": {
				Type:    "list",
				Default: []*ArgNode{},
				Desc:    "forward proxy handlers",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {
								Type:     "string",
								Required: true,
								Desc:     "name of the forward proxy handler",
							},
							"logi": {
								Type:     "ptr",
								Required: true,
								Desc:     "pointer to forward proxy implementation",
							},
							"hosts": {
								Type:    "list",
								Default: []*ArgNode{{Type: "string", Value: "*"}},
								Desc:    "hostnames this forward proxy handles",
								Sub: AssertMap{
									"_": {Type: "string", Desc: DescHostnameFormat},
								},
							},
						},
					},
				},
			},
		},
	},
	"builtin::tcp::det": {
		Type:     "map",
		Required: true,
		Sub: AssertMap{
			"protocols": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "string",
						Enum: []any{"tls", "http", "ssh", "rdp", "socks5", "proxyprotocol", "minecraft"},
					},
				},
			},
			"timeout": {
				Type:    "duration",
				Default: "0s",
				Desc:    "timeout for detection, 0 means no timeout",
			},
			"timeoutprotocol": {
				Type:    "string",
				Desc:    "protocol to assume when timeout",
				Default: "UNKNOWN",
			},
		},
	},
	"builtin::tcp::controller": {
		Type:     "map",
		Required: true,
		Desc:     "TCP connection controller that manages protocol detection and service routing",
		Sub: AssertMap{
			"services": {
				Type: "map",
				Desc: "protocol-specific service handlers, where key is the protocol name (e.g. '' (first inbound), 'TLS', 'HTTP1', 'TLS HTTP2', etc)",
				Sub: AssertMap{
					"_": {
						Type: "list",
						Desc: "ordered list of service handlers for each protocol",
						Sub: AssertMap{
							"_": {
								Type: "map",
								Sub: AssertMap{
									"name": {
										Type:     "string",
										Required: true,
										Desc:     "name of the service handler (used in connection logs)",
									},
									"logi": {
										Type:     "ptr",
										Required: true,
										Desc:     "pointer to service handler implementation (must implement tcp.ServiceHandler)",
									},
								},
							},
						},
					},
				},
			},
		},
	},
	"builtin::tls::reload": {
		Type:     "ptr",
		Required: true,
	},

	"builtin::tcp::listen": {
		Type: "map",
		Sub: AssertMap{
			"AddressBindings": {
				Type: "list",
				Desc: "tcp listen address",
				Sub: AssertMap{
					"_": {Type: "string", Enum: []any{"0.0.0.0:443", "0.0.0.0:80", "0.0.0.0:22"}, AllowNonEnum: true},
				},
			},
			"ptr": {
				Type:     "ptr",
				Required: true,
			},
		},
	},
	"builtin::tcp::proxier": {
		Type: "map",
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
							"backend": {
								Type:     "string",
								Required: true,
							},
							"protocol": {
								Type:     "string",
								Required: true,
							},
						},
					},
				},
			},
		},
	},
	"builtin::tcp::proxyprotocolhandler": {
		Type: "map",
		Sub: AssertMap{
			"allowedsrcs": {
				Type:    "list",
				Default: []*ArgNode{{Type: "string", Value: "127.0.0.1"}},
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
		},
	},
	"builtin::tcp::securehttp": {
		Type: "null",
	},
	"builtin::auth::manager": {
		Type: "map",
		Sub: AssertMap{
			"backends": {
				Type: "list",
				Sub: AssertMap{
					"_": {Type: "ptr"},
				},
			},
			"allowhosts": {
				Type:    "list",
				Default: []*ArgNode{{Type: "string", Value: "*"}},
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
		},
	},

	"builtin::auth::backend::file": {
		Type: "map",
		Sub: AssertMap{
			"users": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {
								Type:     "string",
								Required: true,
								Desc:     "Username",
							},
							"PasswordHash": {
								Type:    "string",
								Default: "",
								Desc:    "Password hash using bcrypt",
							},
							"AllowForwardProxy": {
								Type:    "bool",
								Default: false,
								Desc:    "Allow user to use forward proxy",
							},
							"SSHAuthorizedKeys": {
								Type: "list",
								Sub: AssertMap{
									"_": {Type: "string"},
								},
								Desc: "SSH authorized keys",
							},
						},
					},
				},
			},
		},
	},
	"builtin::auth::backend::ldap": {
		Type: "map",
		Sub: AssertMap{
			"Url":        {Type: "string", Required: true},
			"SearchBase": {Type: "string", Required: true},
			"BindDN":     {Type: "string", Required: true},
			"BindPW":     {Type: "string", Required: true},
		},
	},
	"builtin::auth::policyd": {
		Type: "map",
		Sub: AssertMap{
			"Policies": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name":      {Type: "string", Required: true},
							"Allowance": {Type: "bool", Required: true},
							"Users": {
								Type: "list",
								Desc: "matching users,empty STRING means ALL, empty LIST means NONE",
								Sub: AssertMap{
									"_": {Type: "string"},
								},
							},
							"Hosts": {
								Type: "list",
								Desc: "matching Hosts, empty means none",
								Sub: AssertMap{
									"_": {Type: "string", Desc: DescHostnameFormat},
								},
							},
							"Paths": {
								Type: "list",
								Desc: "matching Paths, empty means all",
								Sub: AssertMap{
									"_": {Type: "string"},
								},
							},
						},
					},
				},
			},
			"backends": {
				Type: "list",
				Sub: AssertMap{
					"_": {Type: "ptr"},
				},
			},
		},
	},
	"builtin::auth::knocked": {
		Type: "map",
		Sub: AssertMap{
			"timeout": {
				Type:    "duration",
				Default: "3s",
			},
		},
	},
	"builtin::http::midware::addservice": {
		Type: "map",
		Desc: "adds additional HTTP services to an existing HTTP middleware",
		Sub: AssertMap{
			"midware": {
				Type:     "ptr",
				Required: true,
				Desc:     "pointer to the target HTTP middleware to add services to",
			},
			"services": {
				Type: "list",
				Desc: "list of HTTP services to add",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"logi": {
								Type:     "ptr",
								Required: true,
								Desc:     "pointer to service handler implementation",
							},
							"hosts": {
								Type: "list",
								Desc: "hostnames this service handles",
								Sub: AssertMap{
									"_": {Type: "string", Desc: DescHostnameFormat},
								},
							},
							"name": {
								Type:     "string",
								Required: true,
								Desc:     "name of the service (used in logs and monitoring)",
							},
						},
					},
				},
			},
		},
	},
	"builtin::dns::server": {
		Type: "map",
		Sub: AssertMap{
			"AddressBindings": {
				Type: "list",
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
			"Domain": {
				Type:    "string",
				Default: "local",
			},
			"Records": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"Name": {
								Type:     "string",
								Required: true,
							},
							"Type": {
								Type:     "string",
								Required: true,
							},
							"Value": {
								Type:     "string",
								Required: true,
							},
							"TTL": {
								Type:    "int",
								Default: 300,
							},
						},
					},
				},
			},
			"Filters": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"Name": {
								Type:     "string",
								Required: true,
							},
							"Allowance": {
								Type:    "bool",
								Default: true,
							},
						},
					},
				},
			},
			"Binds": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"Name": {
								Type:     "string",
								Required: true,
							},
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
	// "builtin::socks5::server": {
	// 	Type: "any",
	// },
	"builtin::http::forwardproxier": {
		Type: "null",
		Desc: "HTTP forward proxy implementation (no configuration needed)",
	},
	"builtin::http::fwdforwardproxier": {
		Type: "map",
		Sub: AssertMap{
			"ProxyURL": {
				Type:     "string",
				Required: true,
			},
		},
	},
	"builtin::http::acme::fileprovider": {
		Type: "map",
		Sub: AssertMap{
			"Hosts": {
				Type: "list",
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
			"WWWRoot": {
				Type:     "string",
				Required: true,
			},
		},
	},
	"builtin::ssh::midware": {
		Type: "map",
		Sub: AssertMap{
			"services": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"name": {
								Type:     "string",
								Required: true,
							},
							"logi": {
								Type:     "ptr",
								Required: true,
							},
						},
					},
				},
			},
			"banner": {
				Type:    "string",
				Default: "Welcome to OpenNG SSH Server\n",
				Desc:    "Dynamic Strings:\n%t: time\n%h: remote ip\n%u: username\n",
			},
			"quotes": {
				Type: "list",
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
			"privatekeys": {
				Type: "list",
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
			"policyd": {
				Type:     "ptr",
				Required: true,
			},
			"logpassword": {
				Type:    "bool",
				Default: false,
			},
		},
	},

	"builtin::ssh::reverseproxier": {
		Type: "map",
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
							"HostName": {
								Type:     "string",
								Required: true,
							},
							"Port": {
								Type:    "int",
								Default: 22,
							},
							"Pubkey": {
								Type: "string",
							},
							"Identity": {
								Type: "string",
							},
							"User": {
								Type: "string",
							},
							"Password": {
								Type: "string",
							},
							"AllowedUsers": {
								Type: "list",
								Desc: "empty means all, when set, only matched users are allowed",
								Sub: AssertMap{
									"_": {Type: "string", Desc: "matching username by regex pattern\nexample: ^root$"},
								},
							},
						},
					},
				},
			},
			"allowdnsquery": {
				Type:    "bool",
				Default: false,
			},
			"privatekeys": {
				Type: "list",
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
		},
	},

	"builtin::ipfilter": {
		Type:     "map",
		Required: true,
		Desc:     "filter connections based on source IP CIDR ranges",
		Sub: AssertMap{
			"blockedcidrs": {
				Type: "list",
				Desc: "list of CIDR ranges to block",
				Sub: AssertMap{
					"_": {Type: "string", Desc: "CIDR notation (e.g. 192.168.1.0/24)"},
				},
			},
			"allowedcidrs": {
				Type: "list",
				Desc: "list of CIDR ranges to allow",
				Sub: AssertMap{
					"_": {Type: "string", Desc: "CIDR notation (e.g. 192.168.1.0/24)"},
				},
			},
			"next": {
				Type:    "ptr",
				Default: nil,
				Desc:    "next service handler if no CIDR match is found",
			},
		},
	},

	"builtin::hostfilter": {
		Type:     "map",
		Required: true,
		Desc:     "filter connections based on HTTP Host header or TLS SNI",
		Sub: AssertMap{
			"allowedhosts": {
				Type: "list",
				Desc: "list of allowed hostnames",
				Sub: AssertMap{
					"_": {Type: "string", Desc: "hostname to allow"},
				},
			},
			"next": {
				Type:    "ptr",
				Default: nil,
				Desc:    "next service handler if hostname is not allowed",
			},
		},
	},
	"builtin::gitlabauth": {
		Type: "map",
		Sub: AssertMap{
			"gitlab_url": {
				Type:     "string",
				Required: true,
			},
			"cache_ttl": {
				Type:    "duration",
				Default: "10s",
			},
			"matchusernames": {
				Type: "list",
				Sub: AssertMap{
					"_": {Type: "string"},
				},
			},
			"prefix": {
				Type:    "string",
				Default: "",
			},
			"next": {
				Type:    "ptr",
				Default: nil,
			},
		},
	},
	"builtin::webui": {
		Type: "map",
		Sub: AssertMap{
			"tcpcontroller": {
				Type:     "ptr",
				Required: true,
			},
			"httpmidware": {
				Type:     "ptr",
				Required: true,
			},
			"tls": {
				Type:     "ptr",
				Required: false,
			},
		},
	},
	"builtin::wireguard::server": {
		Type: "map",
		Sub: AssertMap{
			"ListenPort": {
				Type:     "int",
				Required: true,
			},
			"PrivateKey": {
				Type:     "string",
				Required: true,
			},
			"Address": {
				Type:     "string",
				Required: true,
			},
			"MTU": {
				Type:    "int",
				Default: 1420,
			},
			"Forwarding": {
				Type:    "map",
				Default: map[string]*ArgNode{},
				Sub: AssertMap{
					"EnableTCP": {
						Type:    "bool",
						Default: true,
					},
					"EnableUDP": {
						Type:    "bool",
						Default: true,
					},
					"TCP": {
						Type:    "map",
						Default: map[string]*ArgNode{},
						Sub: AssertMap{
							"CatchTimeout": {
								Type:    "duration",
								Default: "600ms",
							},
							"ConnTimeout": {
								Type:    "duration",
								Default: "3s",
							},
							"KeepaliveIdle": {
								Type:    "duration",
								Default: "60s",
							},
							"KeepaliveInterval": {
								Type:    "duration",
								Default: "30s",
							},
							"KeepaliveCount": {
								Type:    "int",
								Default: 3,
							},
						},
					},
				},
			},
		},
	},
	"builtin::wireguard::addpeers": {
		Type: "map",
		Sub: AssertMap{
			"server": {
				Type:     "ptr",
				Required: true,
			},
			"Peers": {
				Type: "list",
				Sub: AssertMap{
					"_": {
						Type: "map",
						Sub: AssertMap{
							"PublicKey": {
								Type:     "string",
								Required: true,
							},
							"AllowedIPs": {
								Type: "list",
								Sub: AssertMap{
									"_": {Type: "string"},
								},
							},
						},
					},
				},
			},
		},
	},
}

var _builtin_refs = map[string]Inst{
	"builtin::http::reverseproxier": func(spec *ArgNode) (any, error) {
		hosts := spec.MustGet("hosts").ToList()

		allowedhosts := spec.MustGet("allowhosts").ToStringList()

		proxier := http.NewHTTPProxier(allowedhosts)

		for _, host := range hosts {
			name := host.MustGet("name").ToString()
			hosts := host.MustGet("hosts").ToStringList()

			backend := host.MustGet("backend").ToString()
			maxconns := host.MustGet("MaxConnsPerHost").ToInt()
			tlsskip := host.MustGet("TlsSkipVerify").ToBool()

			proxier.Insert(proxier.Len(), name, hosts, backend, maxconns, tlsskip)

			log.Verboseln(fmt.Sprintf("new http reverse host %#v: hosts=%#v backend=%#v maxconns=%d tlsskip=%v", name, hosts, backend, maxconns, tlsskip))
		}

		return proxier, nil
	},
	"builtin::tls": func(spec *ArgNode) (any, error) {
		certs := spec.MustGet("certificates").ToList()

		tls := tls.NewTlsMgr()

		for _, cert := range certs {
			certfile := cert.MustGet("CertFile").ToString()
			keyfile := cert.MustGet("KeyFile").ToString()

			err := tls.LoadCertificate(certfile, keyfile)

			if err != nil {
				return nil, err
			}

			log.Verboseln(fmt.Sprintf("new tls certificate: certfile=%#v keyfile=%#v", certfile, keyfile))
		}

		return tls, nil
	},
	"builtin::http::midware": func(spec *ArgNode) (any, error) {
		services := spec.MustGet("services").ToList()
		cgis := spec.MustGet("cgis").ToList()
		forwards := spec.MustGet("forward").ToList()

		var midware = http.NewHttpMidware([]string{"*"})

		midware.AddCgis(&http.CgiStruct{
			CgiHandler: func(ctx *http.HttpCtx, path string) http.Ret {
				WriteLogo(ctx.Resp)
				return http.RequestEnd
			},
			CgiPaths: []*regexp2.Regexp{regexp2.MustCompile("^/logo$", regexp2.None)},
		})

		for _, srv := range services {
			name := srv.MustGet("name").ToString()
			logi := srv.MustGet("logi")
			_hosts := srv.MustGet("hosts").ToStringList()

			service, ok := logi.Value.(http.Service)
			if !ok {
				return nil, errors.New("ptr " + name + " is not a http.Service")
			}

			var hosts utils.GroupRegexp
			if len(_hosts) == 0 {
				hosts = service.Hosts()
			} else {
				hosts = utils.MustCompileRegexp(dns.Dnsnames2Regexps(_hosts))
			}

			midware.AddServices(&http.ServiceStruct{
				Id:             name,
				Hosts:          hosts,
				ServiceHandler: service.HandleHTTP,
			})

			log.Verboseln(fmt.Sprintf("new http service %#v: hosts=%#v logi=%T", name, hosts.String(), logi.Value))
		}

		for _, cgi := range cgis {
			logi := cgi.MustGet("logi")

			service, ok := logi.Value.(http.Cgi)
			if !ok {
				return nil, errors.New("ptr is not a http.Cgi")
			}

			midware.AddCgis(&http.CgiStruct{
				CgiHandler: service.HandleHTTPCgi,
				CgiPaths:   service.CgiPaths(),
			})
			log.Verboseln(fmt.Sprintf("new http cgi: logi=%T", logi.Value))
		}

		for _, fwd := range forwards {
			name := fwd.MustGet("name").ToString()
			logi := fwd.MustGet("logi")
			_hosts := fwd.MustGet("hosts").ToStringList()

			service, ok := logi.Value.(http.Forward)
			if !ok {
				return nil, errors.New("ptr " + name + " is not a http.Forward")
			}

			var hosts utils.GroupRegexp
			if len(_hosts) == 0 {
				hosts = service.HostsForward()
			} else {
				hosts = utils.MustCompileRegexp(dns.Dnsnames2Regexps(_hosts))
			}

			midware.AddForwardServices(&http.ServiceStruct{
				Id:             name,
				Hosts:          hosts,
				ServiceHandler: service.HandleHTTPForward,
			})
			log.Verboseln(fmt.Sprintf("new http forward service %#v: hosts=%#v logi=%T", name, hosts.String(), logi.Value))
		}

		return midware, nil
	},
	"builtin::tcp::det": func(spec *ArgNode) (any, error) {
		protocols := spec.MustGet("protocols").ToStringList()
		timeout := spec.MustGet("timeout").ToDuration()
		timeoutprotocol := spec.MustGet("timeoutprotocol").ToString()

		var dets []tcp.Detector
		for _, p := range protocols {
			switch p {
			case "tls":
				dets = append(dets, tcp.DetectTLS)
			case "proxyprotocol":
				dets = append(dets, tcp.DetectPROXYPROTOCOL)
			case "ssh":
				dets = append(dets, tcp.DetectSSH)
			case "rdp":
				dets = append(dets, tcp.DetectRDP)
			case "http":
				dets = append(dets, tcp.DetectHTTP)
			case "socks5":
				dets = append(dets, tcp.DetectSOCKS5)
			case "minecraft":
				dets = append(dets, tcp.DetectMinecraft)
			default:
				return nil, errors.New("unknown protocol: " + p)
			}
		}

		log.Verboseln(fmt.Sprintf("new tcp detector: protocols=%#v timeout=%s timeoutprotocol=%s", protocols, timeout.String(), timeoutprotocol))

		return &tcp.Detect{Dets: dets, Timeout: timeout, TimeoutProtocol: timeoutprotocol}, nil
	},
	"builtin::tcp::controller": func(spec *ArgNode) (any, error) {
		services := spec.MustGet("services").ToMap()

		controller := tcp.NewTcpController()

		for name, srvs := range services {
			var _bindings []tcp.ServiceBinding
			for i, srv := range srvs.ToList() {

				_name := srv.MustGet("name").ToString()
				logi := srv.MustGet("logi")
				service, ok := logi.Value.(tcp.ServiceHandler)
				if !ok {
					return nil, errors.New("ptr " + _name + " is not a tcp.ServiceHandler " + fmt.Sprintf("%T %#v", logi.Value, logi.Value))
				}
				_bindings = append(_bindings, tcp.ServiceBinding{
					Name:           _name,
					ServiceHandler: service,
				})

				log.Verboseln(fmt.Sprintf("on tcp %#v[%d]: name=%v logi=%T", name, i, _name, logi.Value))

			}

			controller.Bind(name, _bindings...)
		}

		return controller, nil
	},
	"builtin::tls::reload": func(spec *ArgNode) (any, error) {
		tls, err := spec.Value.(*tls.TlsMgr)
		if !err {
			return nil, errors.New("ptr is not a tls.TlsMgr")
		}

		return nil, tls.Reload()
	},

	"builtin::tcp::listen": func(spec *ArgNode) (any, error) {
		ctl, ok := spec.MustGet("ptr").Value.(interface{ Listen(addr string) error })

		if !ok {
			return nil, errors.New("ptr is not a tcp.Listener")
		}

		for _, addr := range spec.MustGet("AddressBindings").ToStringList() {
			if err := ctl.Listen(addr); err != nil {
				return nil, err
			}
			log.Verboseln(fmt.Sprintf("tcp listen on %v", addr))
		}
		return nil, nil
	},
	"builtin::tcp::proxier": func(spec *ArgNode) (any, error) {
		hosts := spec.MustGet("hosts").ToList()

		proxier := tcp.NewTcpProxier()

		for _, host := range hosts {
			name := host.MustGet("name").ToString()
			backend := host.MustGet("backend").ToString()
			protocol := host.MustGet("protocol").ToString()

			err := proxier.Add(name, backend, protocol)
			if err != nil {
				return nil, err
			}
			log.Verboseln(fmt.Sprintf("new tcp proxy host %#v: backend=%#v protocol=%#v", name, backend, protocol))
		}

		return proxier, nil
	},
	"builtin::tcp::proxyprotocolhandler": func(spec *ArgNode) (any, error) {
		allowedsrcs := spec.MustGet("allowedsrcs").ToStringList()
		log.Verboseln(fmt.Sprintf("new tcp proxy protocol handler: allowedsrcs=%#v", allowedsrcs))
		return tcp.NewTCPProxyProtocolHandler(allowedsrcs), nil
	},
	"builtin::tcp::securehttp": func(spec *ArgNode) (any, error) {
		return http.Redirect2TLS, nil
	},

	"builtin::auth::manager": func(spec *ArgNode) (any, error) {
		backends := spec.MustGet("backends").ToList()

		var authmethods []auth.AuthHandle

		for _, backend := range backends {
			b, ok := backend.Value.(auth.AuthHandle)
			if !ok {
				return nil, errors.New("ptr is not a auth.AuthHandle")
			}
			authmethods = append(authmethods, b)
		}

		log.Verboseln(fmt.Sprintf("new auth manager: backends=%#v", authmethods))

		manager := auth.NewAuthMgr(authmethods,
			utils.MustCompileRegexp(dns.Dnsnames2Regexps(spec.MustGet("allowhosts").ToStringList())))

		return manager, nil
	},
	"builtin::auth::backend::file": func(spec *ArgNode) (any, error) {
		users := spec.MustGet("users").ToList()

		backend := authbackends.NewFileBackend()

		for _, user := range users {
			name := user.MustGet("name").ToString()
			pw := user.MustGet("PasswordHash").ToString()
			allowfp := user.MustGet("AllowForwardProxy").ToBool()
			sshkeys := user.MustGet("SSHAuthorizedKeys").ToStringList()
			var _sshkeys []gossh.PublicKey = nil

			for _, key := range sshkeys {
				pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key))
				if err != nil {
					return nil, err
				}
				_sshkeys = append(_sshkeys, pk)
			}

			backend.SetUser(name, pw, allowfp, _sshkeys, false)

			log.Verboseln(fmt.Sprintf("new auth file user %#v: pwh=%#.11v... allowfp=%v sshkeys=%#.26v", name, pw, allowfp, sshkeys))
		}

		return backend, nil
	},
	"builtin::auth::backend::ldap": func(spec *ArgNode) (any, error) {
		url := spec.MustGet("Url").ToString()
		searchbase := spec.MustGet("SearchBase").ToString()
		binddn := spec.MustGet("BindDN").ToString()
		bindpw := spec.MustGet("BindPW").ToString()

		log.Verboseln(fmt.Sprintf("new auth ldap backend: url=... searchbase=%#v binddn=%#v bindpw=...", searchbase, binddn))
		return authbackends.NewLDAPBackend(url, searchbase, binddn, bindpw), nil
	},
	"builtin::auth::policyd": func(spec *ArgNode) (any, error) {
		policies := spec.MustGet("Policies").ToList()
		backends := spec.MustGet("backends").ToList()

		policyd := auth.NewPBAuth()

		for _, policy := range policies {
			name := policy.MustGet("name").ToString()
			allowance := policy.MustGet("Allowance").ToBool()
			users := policy.MustGet("Users").ToStringList()
			hosts := policy.MustGet("Hosts").ToStringList()
			paths := policy.MustGet("Paths").ToStringList()

			err := policyd.AddPolicy(name, allowance, users, hosts, paths)
			if err != nil {
				return nil, err
			}

			log.Verboseln(fmt.Sprintf("new auth policy %#v: allowance=%v users=%#v hosts=%#v paths=%#v", name, allowance, users, hosts, paths))

		}

		var b []auth.PolicyBackend
		for _, backend := range backends {
			_b, ok := backend.Value.(auth.PolicyBackend)
			if !ok {
				return nil, errors.New("ptr is not a auth.PolicyBackend")
			}
			b = append(b, _b)

			log.Verboseln(fmt.Sprintf("new auth policy backend %T", backend.Value))
		}

		policyd.AddBackends(b)

		return policyd, nil
	},
	"builtin::auth::knocked": func(spec *ArgNode) (any, error) {
		timeout := spec.MustGet("timeout").ToDuration()

		if timeout != 0 {
			panic("not implemented")
		}

		return auth.NewKnockMgr(), nil
	},
	"builtin::dns::server": func(spec *ArgNode) (any, error) {
		records := spec.MustGet("Records").ToList()
		filters := spec.MustGet("Filters").ToList()
		binds := spec.MustGet("Binds").ToList()

		listens := spec.MustGet("AddressBindings").ToStringList()

		Dns := dns.NewServer()

		Dns.SetDomain(spec.MustGet("Domain").ToString())

		for _, record := range records {
			name := record.MustGet("Name").ToString()
			typ := record.MustGet("Type").ToString()
			value := record.MustGet("Value").ToString()
			ttl := record.MustGet("TTL").ToInt()

			Dns.AddRecord(regexp2.MustCompile(dns.Dnsname2Regexp(name), 0), dns.DnsStringTypeToInt(typ), value, uint32(ttl))

			log.Verboseln(fmt.Sprintf("new dns record: name=%#v type=%#v value=%#v ttl=%d", name, typ, value, ttl))
		}

		for _, filter := range filters {
			name := filter.MustGet("Name").ToString()
			allowance := filter.MustGet("Allowance").ToBool()

			err := Dns.AddFilter(regexp2.MustCompile(dns.Dnsname2Regexp(name), 0), allowance)
			if err != nil {
				return nil, err
			}

			log.Verboseln(fmt.Sprintf("new dns filter: name=%#v allowance=%v", name, allowance))
		}

		for _, bind := range binds {
			name := bind.MustGet("Name").ToString()
			addr := bind.MustGet("Addr").ToString()

			err := Dns.AddRecordWithIP(name, addr)
			if err != nil {
				return nil, err
			}

			log.Verboseln(fmt.Sprintf("new dns bind: name=%#v addr=%#v", name, addr))
		}

		for _, listen := range listens {
			go Dns.Listen(listen)

			log.Verboseln(fmt.Sprintf("dns listen: addr=%#v", listen))
		}

		return Dns, nil
	},
	"builtin::http::forwardproxier": func(spec *ArgNode) (any, error) {
		return http.StdForwardProxy{}, nil
	},
	"builtin::http::fwdforwardproxier": func(spec *ArgNode) (any, error) {
		proxyurl := spec.MustGet("ProxyURL").ToString()
		_url, err := url.Parse(proxyurl)
		if err != nil {
			return nil, err
		}

		return &http.FwdForwardProxy{Proxy: _url}, nil
	},
	"builtin::http::acme::fileprovider": func(spec *ArgNode) (any, error) {
		host := spec.MustGet("Hosts").ToStringList()
		wwwroot := spec.MustGet("WWWRoot").ToString()
		acmec := &AcmeWebRoot{
			AllowedHosts: host,
			WWWRoot:      wwwroot,
		}

		log.Verboseln(fmt.Sprintf("new acme file provider: hosts=%#v wwwroot=%#v", host, wwwroot))
		return acmec, nil
	},
	"builtin::webui": func(spec *ArgNode) (any, error) {
		tcpcontroller, ok := spec.MustGet("tcpcontroller").Value.(Reporter)
		if !ok {
			return nil, errors.New("tcp controller ptr is not a Reporter")
		}
		httpmidware, ok := spec.MustGet("httpmidware").Value.(Reporter)
		if !ok {
			return nil, errors.New("http midware ptr is not a Reporter")
		}

		var webui = &UI{tcpcontroller, httpmidware, nil}

		tlsptr, exists := spec.Get("tls")

		if exists == nil {
			tlsmgr, ok := tlsptr.Value.(*tls.TlsMgr)
			if !ok {
				return nil, errors.New("tls ptr is not a tls.TlsMgr")
			}
			webui.TlsMgr = tlsmgr
		}

		return webui, nil
	},
	"builtin::ssh::midware": func(spec *ArgNode) (any, error) {
		services := spec.MustGet("services").ToList()
		banner := spec.MustGet("banner").ToString()
		quotes := spec.MustGet("quotes").ToStringList()
		privatekeys := spec.MustGet("privatekeys").ToStringList()

		logpassword := spec.MustGet("logpassword").ToBool()

		policyd := spec.MustGet("policyd").Value.(interface {
			CheckSSHKey(ctx *ssh.Ctx, key gossh.PublicKey) bool
		}).CheckSSHKey

		var prik []gossh.Signer
		for _, key := range privatekeys {
			pk, err := gossh.ParsePrivateKey([]byte(key))
			if err != nil {
				return nil, err
			}
			prik = append(prik, pk)
		}

		log.Verboseln("got", len(prik), "private keys")

		var _quotes []string
		for _, q := range quotes {
			_quotes = append(_quotes, strings.TrimSpace(q))
		}

		log.Verboseln("got", len(_quotes), "quotes")

		var pwd ssh.PasswordCbFn = nil
		if logpassword {
			pwd = func(ctx *ssh.Ctx, password []byte) bool {
				return false
			}
		}

		midware := ssh.NewSSHController(prik, banner, _quotes, pwd, policyd)

		midware.AddHandler(ssh.SSHLogger{}, utils.MustCompileRegexp([]string{"^.*$"}))
		for _, srv := range services {
			name := srv.MustGet("name").ToString()
			logi := srv.MustGet("logi")

			service, ok := logi.Value.(ssh.ConnHandler)
			if !ok {
				return nil, errors.New("ptr " + name + " is not a ssh.ConnHandler")
			}

			midware.AddHandler(service, utils.MustCompileRegexp([]string{"^.*$"}))

			log.Verboseln(fmt.Sprintf("new ssh service %#v: logi=%T", name, logi.Value))
		}
		return midware, nil
	},
	"builtin::ssh::reverseproxier": func(spec *ArgNode) (any, error) {
		hosts := spec.MustGet("hosts").ToList()
		allowdnsquery := spec.MustGet("allowdnsquery").ToBool()
		privatekeys := spec.MustGet("privatekeys").ToStringList()

		var prik []gossh.Signer
		for _, key := range privatekeys {
			pk, err := gossh.ParsePrivateKey([]byte(key))
			if err != nil {
				return nil, err
			}
			prik = append(prik, pk)
		}

		log.Verboseln("got", len(prik), "default private keys")

		hm := map[string]ssh.Host{}

		for i, host := range hosts {
			name := host.MustGet("name").ToString()
			hostname := host.MustGet("HostName").ToString()
			port := host.MustGet("Port").ToInt()
			pubkey := host.MustGet("Pubkey").ToString()
			identity := host.MustGet("Identity").ToString()
			user := host.MustGet("User").ToString()
			password := host.MustGet("Password").ToString()

			_allowedusers := host.MustGet("AllowedUsers").ToStringList()

			var allowedusers utils.GroupRegexp = nil

			if len(_allowedusers) > 0 {
				allowedusers = utils.MustCompileRegexp(_allowedusers)
			}

			name = strings.ToLower(name)
			var pubkeyf gossh.PublicKey
			if pubkey != "" {
				pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pubkey))
				if err != nil {
					return nil, err
				}
				pubkeyf = pk
			}
			var idk gossh.Signer
			if identity != "" {
				pk, err := gossh.ParsePrivateKey([]byte(identity))
				if err != nil {
					return nil, err
				}
				idk = pk
			}
			hm[name] = ssh.Host{
				Name:   name,
				Addr:   hostname + ":" + strconv.Itoa(port),
				Pubkey: pubkeyf,

				IdentityKey: idk,
				User:        user,
				Password:    password,

				AllowedUsers: allowedusers,
			}
			log.Verboseln(fmt.Sprintf("new ssh reverse host %#v: hostname=%#v port=%d pubkey=%#v allowedusers=%#v identity=... user=... password=...", name, hostname, port, pubkey, allowedusers.String()))

			if i == 0 {
				hm[""] = hm[name]
				log.Verboseln("this is the default host")
			}

		}

		serv := ssh.NewSSHProxier(hm, prik)
		serv.AllowDnsQuery = allowdnsquery

		return serv, nil
	},
	"builtin::ipfilter": func(spec *ArgNode) (any, error) {
		allowedcidrs := spec.MustGet("allowedcidrs").ToStringList()
		blockedcidrs := spec.MustGet("blockedcidrs").ToStringList()
		next := spec.MustGet("next")

		var f = NewIPFilter(allowedcidrs, blockedcidrs)

		if next != nil {
			nextf, ok := next.Value.(tcp.ServiceHandler)
			if !ok {
				return nil, errors.New("ptr is not a http.HttpHandler")
			}
			f.next = nextf
		}

		log.Verboseln(fmt.Sprintf("new ip filter: allowedcidrs=%#v", allowedcidrs))

		return f, nil
	},
	"builtin::hostfilter": func(spec *ArgNode) (any, error) {
		allowedhosts := spec.MustGet("allowedhosts").ToStringList()
		next := spec.MustGet("next")

		var f = &HostFilter{AllowedHosts: allowedhosts}

		if next != nil {
			nextf, ok := next.Value.(tcp.ServiceHandler)
			if !ok {
				return nil, errors.New("ptr is not a http.HttpHandler")
			}
			f.next = nextf
		}

		log.Verboseln(fmt.Sprintf("new host filter: allowedhosts=%#v", allowedhosts))

		return f, nil
	},
	"builtin::gitlabauth": func(spec *ArgNode) (any, error) {
		gitlaburl := spec.MustGet("gitlab_url").ToString()
		cachettl := spec.MustGet("cache_ttl").ToDuration()
		matchusernames := spec.MustGet("matchusernames").ToStringList()
		prefix := spec.MustGet("prefix").ToString()
		next := spec.MustGet("next")

		var f = &GitlabEnhancedPolicydBackend{
			gitlabUrl:     gitlaburl,
			ttl:           cachettl,
			matchUsername: utils.MustCompileRegexp(matchusernames),
			cache:         make(map[string]*SSHKeyCache),
			prefix:        prefix,
		}

		if next != nil {
			nextf, ok := next.Value.(auth.PolicyBackend)
			if !ok {
				return nil, errors.New("ptr is not a auth.PolicyBackend" + fmt.Sprintf("%T", next.Value))
			}
			f.PolicyBackend = nextf
		}

		log.Verboseln(fmt.Sprintf("new gitlab auth: gitlaburl=%#v cachettl=%v matchusernames=%#v next=%#v", gitlaburl, f.ttl.String(), f.matchUsername.String(), next))
		return f, nil
	},
	"builtin::http::midware::addservice": func(spec *ArgNode) (any, error) {
		midware, ok := spec.MustGet("midware").Value.(*http.Midware)
		if !ok {
			return nil, errors.New("ptr is not a http.Midware")
		}

		services := spec.MustGet("services").ToList()

		for _, srv := range services {
			name := srv.MustGet("name").ToString()
			logi := srv.MustGet("logi")
			_hosts := srv.MustGet("hosts").ToStringList()

			service, ok := logi.Value.(http.Service)
			if !ok {
				return nil, errors.New("ptr " + name + " is not a http.Service")
			}

			var hosts utils.GroupRegexp
			if len(_hosts) == 0 {
				hosts = service.Hosts()
			} else {
				hosts = utils.MustCompileRegexp(dns.Dnsnames2Regexps(_hosts))
			}

			midware.AddServices(&http.ServiceStruct{
				Id:             name,
				Hosts:          hosts,
				ServiceHandler: service.HandleHTTP,
			})

			log.Verboseln(fmt.Sprintf("new http service %#v: hosts=%#v logi=%T", name, hosts.String(), logi.Value))
		}

		return nil, nil

	},
	// "builtin::socks5::server": func(spec *ArgNode) (any, error) {
	// 	policyd := spec
	// 	var p socks.Socks5AuthFn = nil
	// 	if policyd != nil {
	// 		__p, ok := policyd.Value.(interface {
	// 			HandleSocks5(username string, password string, userAddr string) bool
	// 		})

	// 		if !ok {
	// 			return nil, errors.New("ptr is not a socks.Socks5AuthFn")
	// 		}

	// 		p = __p.HandleSocks5

	// 	}
	// 	return socks.NewSocks5Server(p), nil
	// },
	"builtin::wireguard::server": func(spec *ArgNode) (any, error) {
		listenport := spec.MustGet("ListenPort").ToInt()
		privatekey := spec.MustGet("PrivateKey").ToString()
		address := spec.MustGet("Address").ToString()
		mtu := spec.MustGet("MTU").ToInt()

		forwarding := spec.MustGet("Forwarding")
		enabletcp := forwarding.MustGet("EnableTCP").ToBool()
		enableudp := forwarding.MustGet("EnableUDP").ToBool()
		tcp := forwarding.MustGet("TCP")
		catchtimeout := tcp.MustGet("CatchTimeout").ToDuration()
		conntimeout := tcp.MustGet("ConnTimeout").ToDuration()
		keepaliveidle := tcp.MustGet("KeepaliveIdle").ToDuration()
		keepaliveinterval := tcp.MustGet("KeepaliveInterval").ToDuration()
		keepalivecount := tcp.MustGet("KeepaliveCount").ToInt()

		cfg := &wireguard.WireGuardConfig{
			ListenPort: listenport,
			PrivateKey: privatekey,
			Address:    address,
			MTU:        mtu,

			EnableTCP: enabletcp,
			EnableUDP: enableudp,

			TcpCatchTimeout:      catchtimeout,
			TcpConnTimeout:       conntimeout,
			TcpKeepaliveIdle:     keepaliveidle,
			TcpKeepaliveInterval: keepaliveinterval,
			TcpKeepAliveCount:    keepalivecount,
		}

		return wireguard.NewWireGuardServer(cfg)

	},

	"builtin::wireguard::addpeers": func(spec *ArgNode) (any, error) {
		peers := spec.MustGet("Peers").ToList()
		server := spec.MustGet("server").Value.(*wireguard.WireGuardServer)

		for _, peer := range peers {
			publickey := peer.MustGet("PublicKey").ToString()
			allowedips := peer.MustGet("AllowedIPs").ToStringList()

			err := server.AddPeer(publickey, allowedips)
			if err != nil {
				return nil, err
			}
		}

		return nil, nil
	},
}
