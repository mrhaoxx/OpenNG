package misc

import (
	"bufio"
	"net"
	stdhttp "net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	ngnet "github.com/mrhaoxx/OpenNG/net"

	netgate "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/auth"
	"github.com/mrhaoxx/OpenNG/modules/ssh"
	"github.com/mrhaoxx/OpenNG/modules/tcp"
	zlog "github.com/rs/zerolog/log"
	gossh "golang.org/x/crypto/ssh"
)

type AcmeWebRoot struct {
	AllowedHosts []string
	WWWRoot      string
}

func (a *AcmeWebRoot) Handle(conn *tcp.Conn) tcp.SerRet {
	_req, ok := conn.Load(tcp.KeyHTTPRequest)
	if !ok {
		return tcp.Continue
	}

	req, ok := _req.(*stdhttp.Request)

	if !ok {
		return tcp.Continue
	}

	if !strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
		return tcp.Continue
	}
	for _, h := range a.AllowedHosts {
		if req.Host == h {
			goto allowed
		}
	}
	return tcp.Continue

allowed:
	s := stdhttp.FileServer(stdhttp.Dir(a.WWWRoot))
	stdhttp.Serve(ngnet.ConnGetSocket(conn.TopConn()), stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		s.ServeHTTP(w, r)
	}))
	return tcp.Close

}

type IpFilter struct {
	allowedCIDR map[string]*net.IPNet
	blockedCIDR map[string]*net.IPNet
	next        tcp.ServiceHandler
}

func (filter *IpFilter) Handle(c *tcp.Conn) tcp.SerRet {
	// Check if the IP is allowed
	host, _, err := net.SplitHostPort(c.Addr().String())
	if err != nil {
		panic(err)
	}

	for _, v := range filter.blockedCIDR {
		if v.Contains(net.ParseIP(host)) {
			return tcp.Close
		}
	}

	for _, v := range filter.allowedCIDR {
		if v.Contains(net.ParseIP(host)) {
			return tcp.Continue
		}
	}

	if filter.next != nil {
		return filter.next.Handle(c)
	}

	return tcp.Close
}

func NewIPFilter(allowedCIDR []string, blockedCIDR []string) *IpFilter {
	filter := &IpFilter{
		allowedCIDR: make(map[string]*net.IPNet),
		blockedCIDR: make(map[string]*net.IPNet),
	}
	for _, v := range allowedCIDR {
		_, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			panic(err)
		}
		filter.allowedCIDR[v] = ipnet
	}

	for _, v := range blockedCIDR {
		_, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			panic(err)
		}
		filter.blockedCIDR[v] = ipnet
	}

	return filter
}

type HostFilter struct {
	AllowedHosts []string
	next         tcp.ServiceHandler
}

func (s *HostFilter) Handle(conn *tcp.Conn) tcp.SerRet {

	switch conn.TopProtocol() {
	case "HTTP1":
		_req, ok := conn.Load(tcp.KeyHTTPRequest)
		if !ok {
			return tcp.Close
		}

		req, ok := _req.(*stdhttp.Request)

		if !ok {
			return tcp.Close
		}

		for _, h := range s.AllowedHosts {
			if req.Host == h {
				return tcp.Continue
			}
		}
	case "TLS":
		_req, ok := conn.Load(tcp.KeyTlsSni)
		if !ok {
			return tcp.Close
		}
		sni, ok := _req.(string)
		if !ok {
			return tcp.Close
		}
		for _, h := range s.AllowedHosts {
			if sni == h {
				return tcp.Continue
			}
		}
	}
	if s.next != nil {
		return s.next.Handle(conn)
	}
	return tcp.Close
}

type SSHKeyCache struct {
	sshKeys []gossh.PublicKey

	time.Time
}

type GitlabEnhancedPolicydBackend struct {
	auth.PolicyBackend

	gitlabUrl     string
	matchUsername netgate.GroupRegexp
	prefix        string
	ttl           time.Duration

	cache     map[string]*SSHKeyCache
	cachelock sync.RWMutex
}

func (g *GitlabEnhancedPolicydBackend) CheckPassword(username string, password string) bool {
	if g.PolicyBackend == nil {
		return false
	}
	return g.PolicyBackend.CheckPassword(username, password)
}

func (g *GitlabEnhancedPolicydBackend) CheckSSHKey(ctx *ssh.Ctx, key gossh.PublicKey) bool {

	rus, ok := strings.CutPrefix(ctx.User, g.prefix)

	if !ok || !g.matchUsername.MatchString(ctx.User) {
		if g.PolicyBackend == nil {
			return false
		}
		return g.PolicyBackend.CheckSSHKey(ctx, key)
	}

	// gitlabUrl + username + .keys
	// https://gitlab.com/username.keys

	if strings.ContainsAny(ctx.User, "./+") {
		return false
	}

	if !g.PolicyBackend.ExistsUser(ctx.User) {
		return false
	}

	g.cachelock.RLock()
	cache, ok := g.cache[ctx.User]
	g.cachelock.RUnlock()

	if !ok || cache.Time.Add(g.ttl).Before(time.Now()) {

		url := g.gitlabUrl + rus + ".keys"

		zlog.Info().
			Bool("ok", ok).
			Interface("cache", cache).
			Str("url", url).
			Msg("gitlab")

		resp, err := stdhttp.Get(url)

		if err != nil {
			zlog.Info().
				Str("type", "gitlab/get").
				Str("url", url).
				Str("error", err.Error()).
				Msg("gitlab")
			return false
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return false
		}

		keys := []gossh.PublicKey{}

		scanner := bufio.NewScanner(resp.Body)

		for scanner.Scan() {
			key, _, _, _, err := gossh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				continue
			}
			keys = append(keys, key)
		}

		cache = &SSHKeyCache{
			sshKeys: keys,
			Time:    time.Now(),
		}

		g.cachelock.Lock()
		g.cache[ctx.User] = cache
		g.cachelock.Unlock()
	}

	for _, k := range cache.sshKeys {
		if k.Type() == key.Type() && reflect.DeepEqual(k.Marshal(), key.Marshal()) {
			return true
		}
	}

	return g.PolicyBackend.CheckSSHKey(ctx, key)
}

func (g *GitlabEnhancedPolicydBackend) AllowForwardProxy(username string) bool {
	if g.PolicyBackend == nil {
		return false
	}
	return g.PolicyBackend.AllowForwardProxy(username)
}

func NewUdpLogger(address string) *udpLogger {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		panic(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		panic(err)
	}
	return &udpLogger{UDPConn: conn}
}

type udpLogger struct {
	*net.UDPConn
}
