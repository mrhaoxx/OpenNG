package misc

import (
	"time"

	ng "github.com/mrhaoxx/OpenNG"
	authsdk "github.com/mrhaoxx/OpenNG/modules/auth"
	"github.com/mrhaoxx/OpenNG/modules/ngtcp"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
	"github.com/rs/zerolog/log"
)

func init() {
	ng.RegisterFunc("http::acme::fileprovider", NewAcmeFileProvider)
	ng.RegisterFunc("ipfilter", NewIpFilterFromConfig)
	ng.RegisterFunc("hostfilter", NewHostFilterFromConfig)
	ng.RegisterFunc("gitlabauth", NewGitlabAuthFromConfig)
}

// --- http::acme::fileprovider ---

type AcmeConfig struct {
	Hosts   []string `ng:"Hosts"`
	WWWRoot string   `ng:"WWWRoot,required"`
}

func NewAcmeFileProvider(cfg AcmeConfig) (*AcmeWebRoot, error) {
	log.Debug().Strs("hosts", cfg.Hosts).Str("wwwroot", cfg.WWWRoot).Msg("new acme file provider")
	return &AcmeWebRoot{
		AllowedHosts: cfg.Hosts,
		WWWRoot:      cfg.WWWRoot,
	}, nil
}

// --- ipfilter ---

type IpFilterConfig struct {
	BlockedCIDRs []string     `ng:"blockedcidrs" desc:"CIDR ranges to block"`
	AllowedCIDRs []string     `ng:"allowedcidrs" desc:"CIDR ranges to allow"`
	Next         ngtcp.Service `ng:"next,allownil" desc:"next service if no CIDR match"`
}

func NewIpFilterFromConfig(cfg IpFilterConfig) (*IpFilter, error) {
	filter := NewIPFilter(cfg.AllowedCIDRs, cfg.BlockedCIDRs)
	if cfg.Next != nil {
		filter.SetNext(cfg.Next)
	}
	log.Debug().Strs("allowedcidrs", cfg.AllowedCIDRs).Msg("new ip filter")
	return filter, nil
}

// --- hostfilter ---

type HostFilterConfig struct {
	AllowedHosts []string     `ng:"allowedhosts" desc:"hostnames to allow"`
	Next         ngtcp.Service `ng:"next,allownil"`
}

func NewHostFilterFromConfig(cfg HostFilterConfig) (*HostFilter, error) {
	filter := &HostFilter{AllowedHosts: cfg.AllowedHosts}
	if cfg.Next != nil {
		filter.SetNext(cfg.Next)
	}
	log.Debug().Strs("allowedhosts", cfg.AllowedHosts).Msg("new host filter")
	return filter, nil
}

// --- gitlabauth ---

type GitlabAuthConfig struct {
	GitlabURL      ngnet.URL       `ng:"gitlab_url,required"`
	CacheTTL       time.Duration   `ng:"cache_ttl" type:"duration" default:"10s"`
	MatchUsernames ng.RegexpSlice  `ng:"matchusernames"`
	Prefix         string          `ng:"prefix"`
	Next           authsdk.PolicyBackend `ng:"next,allownil"`
}

func NewGitlabAuthFromConfig(cfg GitlabAuthConfig) (*GitlabEnhancedPolicydBackend, error) {
	backend := NewGitlabEnhancedPolicydBackend(cfg.GitlabURL.String(), cfg.CacheTTL, cfg.MatchUsernames.GroupRegexp(), cfg.Prefix)
	if cfg.Next != nil {
		backend.SetPolicyBackend(cfg.Next)
	}
	return backend, nil
}
