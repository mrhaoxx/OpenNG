package ngssh

import (
	"errors"
	"strconv"
	"strings"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/ngtcp"
	"github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	ng.RegisterFunc("ssh::midware", NewSSHMidwareFromConfig)
	ng.RegisterFunc("ssh::reverseproxier", NewSSHReverseProxierFromConfig)
}

// --- ssh::midware ---

type SSHServiceConfig struct {
	Name string  `ng:"name,required"`
	Logi Service `ng:"logi,required"`
}

type SSHMidwareConfig struct {
	Services    []SSHServiceConfig `ng:"services"`
	Banner      string             `ng:"banner" desc:"Dynamic Strings:\n%t: time\n%h: remote ip\n%u: username\n"`
	Quotes      []string           `ng:"quotes"`
	PrivateKeys []string           `ng:"privatekeys"`
	Policyd     interface {
		CheckSSHKey(ctx *Ctx, key gossh.PublicKey) bool
	} `ng:"policyd,required"`
	LogPassword bool `ng:"logpassword"`
}

func NewSSHMidwareFromConfig(cfg SSHMidwareConfig) (ngtcp.Service, error) {
	banner := cfg.Banner
	if banner == "" {
		banner = "Welcome to OpenNG SSH Server\n"
	}

	var prik []gossh.Signer
	for _, key := range cfg.PrivateKeys {
		pk, err := gossh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, err
		}
		prik = append(prik, pk)
	}

	log.Debug().Int("count", len(prik)).Msg("got private keys")

	var trimmedQuotes []string
	for _, q := range cfg.Quotes {
		trimmedQuotes = append(trimmedQuotes, strings.TrimSpace(q))
	}

	log.Debug().Int("count", len(trimmedQuotes)).Msg("got quotes")

	var pwd PasswordCbFn
	if cfg.LogPassword {
		pwd = func(ctx *Ctx, password []byte) bool {
			return false
		}
	}

	midware := NewSSHController(prik, banner, trimmedQuotes, pwd, cfg.Policyd.CheckSSHKey)

	for _, srv := range cfg.Services {
		midware.AddHandler(srv.Logi)
		log.Debug().Str("name", srv.Name).Msg("new ssh service")
	}

	return midware, nil
}

// --- ssh::reverseproxier ---

type SSHHostConfig struct {
	Name         string         `ng:"name,required"`
	HostName     string         `ng:"HostName,required" type:"hostname"`
	Port         int            `ng:"Port" default:"22"`
	Pubkey       string         `ng:"Pubkey"`
	Identity     string         `ng:"Identity"`
	User         string         `ng:"User"`
	Password     string         `ng:"Password"`
	AllowedUsers ng.RegexpSlice `ng:"AllowedUsers" desc:"empty means all, when set, only matched users are allowed"`
}

type SSHReverseProxierConfig struct {
	Hosts         []SSHHostConfig `ng:"hosts"`
	AllowDNSQuery bool            `ng:"allowdnsquery"`
	PrivateKeys   []string        `ng:"privatekeys"`
}

func NewSSHReverseProxierFromConfig(cfg SSHReverseProxierConfig) (Service, error) {
	var prik []gossh.Signer
	for _, key := range cfg.PrivateKeys {
		pk, err := gossh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, err
		}
		prik = append(prik, pk)
	}

	log.Debug().Int("count", len(prik)).Msg("got default private keys")

	hostMap := map[string]Host{}

	for i, host := range cfg.Hosts {
		lowered := strings.ToLower(host.Name)

		var parsedPubkey gossh.PublicKey
		if host.Pubkey != "" {
			pk, _, _, _, err := gossh.ParseAuthorizedKey([]byte(host.Pubkey))
			if err != nil {
				return nil, err
			}
			parsedPubkey = pk
		}

		var identityKey gossh.Signer
		if host.Identity != "" {
			pk, err := gossh.ParsePrivateKey([]byte(host.Identity))
			if err != nil {
				return nil, errors.New("failed to parse identity key for host " + host.Name + ": " + err.Error())
			}
			identityKey = pk
		}

		hostMap[lowered] = Host{
			Name:         lowered,
			Addr:         host.HostName + ":" + strconv.Itoa(host.Port),
			Pubkey:       parsedPubkey,
			IdentityKey:  identityKey,
			User:         host.User,
			Password:     host.Password,
			AllowedUsers: host.AllowedUsers.GroupRegexp(),
		}

		if i == 0 {
			hostMap[""] = hostMap[lowered]
			log.Debug().Msg("this is the default host")
		}
	}

	srv := NewSSHProxier(hostMap, prik)
	srv.AllowDnsQuery = cfg.AllowDNSQuery

	return srv, nil
}
