package ssh

import (
	"errors"
	"reflect"
	"strconv"
	"strings"

	ng "github.com/mrhaoxx/OpenNG"
	sshsdk "github.com/mrhaoxx/OpenNG/pkg/ngssh"
	"github.com/mrhaoxx/OpenNG/pkg/ngtcp"
	"github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	registerMidware()
	registerReverseProxier()
}

func registerMidware() {
	ng.Register("ssh::midware",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"services": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name": {Type: "string", Required: true},
								"logi": {Type: "ptr", Required: true},
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
					Sub: ng.AssertMap{
						"_": {Type: "string"},
					},
				},
				"privatekeys": {
					Type: "list",
					Sub: ng.AssertMap{
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
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[ngtcp.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			services := spec.MustGet("services").ToList()
			banner := spec.MustGet("banner").ToString()
			quotes := spec.MustGet("quotes").ToStringList()
			privateKeys := spec.MustGet("privatekeys").ToStringList()

			logPassword := spec.MustGet("logpassword").ToBool()

			policyd := spec.MustGet("policyd").Value.(interface {
				CheckSSHKey(ctx *sshsdk.Ctx, key gossh.PublicKey) bool
			}).CheckSSHKey

			var prik []gossh.Signer
			for _, key := range privateKeys {
				pk, err := gossh.ParsePrivateKey([]byte(key))
				if err != nil {
					return nil, err
				}
				prik = append(prik, pk)
			}

			log.Debug().Int("count", len(prik)).Msg("got private keys")

			var trimmedQuotes []string
			for _, q := range quotes {
				trimmedQuotes = append(trimmedQuotes, strings.TrimSpace(q))
			}

			log.Debug().Int("count", len(trimmedQuotes)).Msg("got quotes")

			var pwd sshsdk.PasswordCbFn
			if logPassword {
				pwd = func(ctx *sshsdk.Ctx, password []byte) bool {
					return false
				}
			}

			midware := sshsdk.NewSSHController(prik, banner, trimmedQuotes, pwd, policyd)

			for _, srv := range services {
				name := srv.MustGet("name").ToString()
				logi := srv.MustGet("logi")

				handler, ok := logi.Value.(sshsdk.Service)
				if !ok {
					return nil, errors.New("ptr " + name + " is not a ssh.ConnHandler")
				}

				midware.AddHandler(handler)

				log.Debug().Str("name", name).Type("logi", logi.Value).Msg("new ssh service")
			}
			return midware, nil
		},
	)
}

func registerReverseProxier() {
	ng.Register("ssh::reverseproxier",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"hosts": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name":     {Type: "string", Required: true},
								"HostName": {Type: "hostname", Required: true},
								"Port":     {Type: "int", Default: 22},
								"Pubkey":   {Type: "string"},
								"Identity": {Type: "string"},
								"User":     {Type: "string"},
								"Password": {Type: "string"},
								"AllowedUsers": {
									Type: "list",
									Desc: "empty means all, when set, only matched users are allowed",
									Sub: ng.AssertMap{
										"_": {Type: "regexp", Desc: "matching username by regex pattern\nexample: ^root$"},
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
					Sub: ng.AssertMap{
						"_": {Type: "string"},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[sshsdk.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			hosts := spec.MustGet("hosts").ToList()
			allowDNSQuery := spec.MustGet("allowdnsquery").ToBool()
			privateKeys := spec.MustGet("privatekeys").ToStringList()

			var prik []gossh.Signer
			for _, key := range privateKeys {
				pk, err := gossh.ParsePrivateKey([]byte(key))
				if err != nil {
					return nil, err
				}
				prik = append(prik, pk)
			}

			log.Debug().Int("count", len(prik)).Msg("got default private keys")

			hostMap := map[string]sshsdk.Host{}

			for i, host := range hosts {
				name := host.MustGet("name").ToString()
				hostname := host.MustGet("HostName").ToString()
				port := host.MustGet("Port").ToInt()
				pubkey := host.MustGet("Pubkey").ToString()
				identity := host.MustGet("Identity").ToString()
				user := host.MustGet("User").ToString()
				password := host.MustGet("Password").ToString()

				allowedUsers := host.MustGet("AllowedUsers").ToGroupRegexp()

				lowered := strings.ToLower(name)
				var parsedPubkey gossh.PublicKey
				if pubkey != "" {
					pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pubkey))
					if err != nil {
						return nil, err
					}
					parsedPubkey = pk
				}

				var identityKey gossh.Signer
				if identity != "" {
					pk, err := gossh.ParsePrivateKey([]byte(identity))
					if err != nil {
						return nil, err
					}
					identityKey = pk
				}

				hostMap[lowered] = sshsdk.Host{
					Name:         lowered,
					Addr:         hostname + ":" + strconv.Itoa(port),
					Pubkey:       parsedPubkey,
					IdentityKey:  identityKey,
					User:         user,
					Password:     password,
					AllowedUsers: allowedUsers,
				}

				if i == 0 {
					hostMap[""] = hostMap[lowered]
					log.Debug().Msg("this is the default host")
				}
			}

			srv := sshsdk.NewSSHProxier(hostMap, prik)
			srv.AllowDnsQuery = allowDNSQuery

			return srv, nil
		},
	)
}
