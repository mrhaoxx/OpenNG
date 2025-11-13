package auth

import (
	"reflect"

	ng "github.com/mrhaoxx/OpenNG"
	authsdk "github.com/mrhaoxx/OpenNG/pkg/auth"
	authbackend "github.com/mrhaoxx/OpenNG/pkg/auth/backend"
	http "github.com/mrhaoxx/OpenNG/pkg/nghttp"
	"github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	ng.Register("auth::manager",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"backends": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {Type: "ptr", Impls: []reflect.Type{
							ng.TypeOf[authsdk.AuthHandle](),
						}},
					},
				},
				"allowhosts": {
					Type:    "list",
					Default: []*ng.ArgNode{{Type: "hostname", Value: "*"}},
					Sub: ng.AssertMap{
						"_": {Type: "hostname"},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[http.Service](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			backends := spec.MustGet("backends").ToList()
			var authmethods []authsdk.AuthHandle

			for _, backend := range backends {
				authmethods = append(authmethods, backend.Value.(authsdk.AuthHandle))
			}

			manager := authsdk.NewAuthMgr(authmethods,
				spec.MustGet("allowhosts").ToGroupRegexp())

			return manager, nil
		},
	)

	ng.Register("auth::backend::file",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"users": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
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
									Desc: "SSH authorized keys",
									Sub: ng.AssertMap{
										"_": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[authsdk.PolicyBackend](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			users := spec.MustGet("users").ToList()
			backend := authbackend.NewFileBackend()

			for _, user := range users {
				name := user.MustGet("name").ToString()
				pw := user.MustGet("PasswordHash").ToString()
				allowfp := user.MustGet("AllowForwardProxy").ToBool()
				sshkeys := user.MustGet("SSHAuthorizedKeys").ToStringList()

				var parsedKeys []gossh.PublicKey
				for _, key := range sshkeys {
					pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key))
					if err != nil {
						return nil, err
					}
					parsedKeys = append(parsedKeys, pk)
				}

				backend.SetUser(name, pw, allowfp, parsedKeys, false)
			}

			return backend, nil
		},
	)

	ng.Register("auth::backend::ldap",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"Url":        {Type: "url", Required: true},
				"SearchBase": {Type: "string", Required: true},
				"BindDN":     {Type: "string", Required: true},
				"BindPW":     {Type: "string", Required: true},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[authsdk.PolicyBackend](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			url := spec.MustGet("Url").ToURL()
			searchBase := spec.MustGet("SearchBase").ToString()
			bindDN := spec.MustGet("BindDN").ToString()
			bindPW := spec.MustGet("BindPW").ToString()

			log.Debug().
				Str("searchbase", searchBase).
				Str("binddn", bindDN).
				Msg("new auth ldap backend")

			return authbackend.NewLDAPBackend(url, searchBase, bindDN, bindPW), nil
		},
	)

	ng.Register("auth::policyd",
		ng.Assert{
			Type: "map",
			Sub: ng.AssertMap{
				"Policies": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {
							Type: "map",
							Sub: ng.AssertMap{
								"name":      {Type: "string", Required: true},
								"Allowance": {Type: "bool", Required: true},
								"Users": {
									Type: "list",
									Desc: "matching users,empty STRING means ALL, empty LIST means NONE",
									Sub: ng.AssertMap{
										"_": {Type: "string"},
									},
								},
								"Hosts": {
									Type: "list",
									Desc: "matching Hosts, empty means none",
									Sub: ng.AssertMap{
										"_": {Type: "hostname"},
									},
								},
								"Paths": {
									Type: "list",
									Desc: "matching Paths, empty means all",
									Sub: ng.AssertMap{
										"_": {Type: "regexp"},
									},
								},
							},
						},
					},
				},
				"backends": {
					Type: "list",
					Sub: ng.AssertMap{
						"_": {Type: "ptr", Impls: []reflect.Type{
							ng.TypeOf[authsdk.PolicyBackend](),
						}},
					},
				},
			},
		},
		ng.Assert{
			Type: "ptr",
			Impls: []reflect.Type{
				ng.TypeOf[authsdk.AuthHandle](),
			},
		},
		func(spec *ng.ArgNode) (any, error) {
			policies := spec.MustGet("Policies").ToList()
			backends := spec.MustGet("backends").ToList()

			policyd := authsdk.NewPBAuth()

			for _, policy := range policies {
				name := policy.MustGet("name").ToString()
				allowance := policy.MustGet("Allowance").ToBool()
				users := policy.MustGet("Users").ToStringList()
				hosts := policy.MustGet("Hosts").ToGroupRegexp()
				paths := policy.MustGet("Paths").ToGroupRegexp()

				if err := policyd.AddPolicy(name, allowance, users, hosts, paths); err != nil {
					return nil, err
				}
			}

			var policyBackends []authsdk.PolicyBackend
			for _, backend := range backends {
				policyBackends = append(policyBackends, backend.Value.(authsdk.PolicyBackend))
			}

			policyd.AddBackends(policyBackends)

			return policyd, nil
		},
	)

}
