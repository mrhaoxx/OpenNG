package auth

import (
	ng "github.com/mrhaoxx/OpenNG"
	authbackend "github.com/mrhaoxx/OpenNG/modules/auth/backend"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	ng.RegisterFunc("auth::manager", NewAuthManagerFromConfig)
	ng.RegisterFunc("auth::backend::file", NewFileBackendFromConfig)
	ng.RegisterFunc("auth::backend::ldap", NewLDAPBackendFromConfig)
	ng.RegisterFunc("auth::policyd", NewPolicydFromConfig)
}

// --- auth::manager ---

type AuthManagerConfig struct {
	Backends   []AuthHandle             `ng:"backends"`
	Allowhosts ng.HostnameSliceDefault  `ng:"allowhosts"`
}

func NewAuthManagerFromConfig(cfg AuthManagerConfig) (*AuthMgr, error) {
	return NewAuthMgr(cfg.Backends, cfg.Allowhosts.GroupRegexp()), nil
}

// --- auth::backend::file ---

type FileUserConfig struct {
	Name                  string   `ng:"name,required"`
	PasswordHash          string   `ng:"PasswordHash"`
	AllowForwardProxy     bool     `ng:"AllowForwardProxy"`
	SSHAuthorizedKeys     []string `ng:"SSHAuthorizedKeys"`
	ClientCertFingerprints []string `ng:"ClientCertFingerprints"`
}

type FileBackendConfig struct {
	Users []FileUserConfig `ng:"users"`
}

func NewFileBackendFromConfig(cfg FileBackendConfig) (*authbackend.FileBackend, error) {
	backend := authbackend.NewFileBackend()

	for _, user := range cfg.Users {
		var parsedKeys []gossh.PublicKey
		for _, key := range user.SSHAuthorizedKeys {
			pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(key))
			if err != nil {
				return nil, err
			}
			parsedKeys = append(parsedKeys, pk)
		}

		backend.SetUser(user.Name, user.PasswordHash, user.AllowForwardProxy, parsedKeys, false, user.ClientCertFingerprints)
	}

	return backend, nil
}

// --- auth::backend::ldap ---

type LDAPBackendConfig struct {
	URL        ngnet.URL `ng:"Url,required"`
	SearchBase string    `ng:"SearchBase,required"`
	BindDN     string    `ng:"BindDN,required"`
	BindPW     string    `ng:"BindPW,required"`
}

func NewLDAPBackendFromConfig(cfg LDAPBackendConfig) (*authbackend.LDAPBackend, error) {
	log.Debug().
		Str("searchbase", cfg.SearchBase).
		Str("binddn", cfg.BindDN).
		Msg("new auth ldap backend")

	u := cfg.URL
	return authbackend.NewLDAPBackend(&u, cfg.SearchBase, cfg.BindDN, cfg.BindPW), nil
}

// --- auth::policyd ---

type PolicyRuleConfig struct {
	Name      string           `ng:"name,required"`
	Allowance bool             `ng:"Allowance,required"`
	Users     []string         `ng:"Users" desc:"matching users, empty STRING means ALL, empty LIST means NONE"`
	Hosts     ng.HostnameSlice `ng:"Hosts" desc:"matching Hosts, empty means none"`
	Paths     ng.RegexpSlice   `ng:"Paths" desc:"matching Paths, empty means all"`
}

type CertMappingConfig struct {
	Fingerprint string `ng:"Fingerprint,required" desc:"SHA256 fingerprint of client TLS certificate"`
	Username    string `ng:"Username,required" desc:"Username to authenticate as"`
}

type PolicydConfig struct {
	Policies     []PolicyRuleConfig  `ng:"Policies"`
	Backends     []PolicyBackend     `ng:"backends"`
	CertMappings []CertMappingConfig `ng:"CertMappings" desc:"Client certificate fingerprint to username mappings"`
}

func NewPolicydFromConfig(cfg PolicydConfig) (*PolicyBaseAuth, error) {
	policyd := NewPBAuth()

	for _, p := range cfg.Policies {
		if err := policyd.AddPolicy(p.Name, p.Allowance, p.Users, p.Hosts.GroupRegexp(), p.Paths.GroupRegexp()); err != nil {
			return nil, err
		}
	}

	policyd.AddBackends(cfg.Backends)

	for _, m := range cfg.CertMappings {
		policyd.AddCertMapping(m.Fingerprint, m.Username)
	}

	return policyd, nil
}
