package auth

import (
	"math/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	zlog "github.com/rs/zerolog/log"
)

type session struct {
	lastseen time.Time
	active   uint64

	muS      sync.Mutex
	username string
	src      int
}

func (u *session) id() string {
	return "[" + strconv.Itoa(u.src) + "]" + u.username
}

func (u *session) renew() {
	u.muS.Lock()
	u.lastseen = time.Now()
	u.muS.Unlock()
}

func (p *PolicyBaseAuth) at(session string) *session {
	p.muSession.RLock()
	defer p.muSession.RUnlock()
	return p.sessions[session]
}

func (mgr *PolicyBaseAuth) generateSession(username string, src int) string {
	var rand = randString(16)
	mgr.muSession.Lock()
	mgr.sessions[rand] = &session{
		lastseen: time.Now(),
		active:   0,
		muS:      sync.Mutex{},
		username: username,
		src:      src,
	}
	mgr.muSession.Unlock()
	return rand
}

func (mgr *PolicyBaseAuth) rmSession(session string) {
	if session == "" {
		return
	}
	mgr.muSession.Lock()
	delete(mgr.sessions, session)
	mgr.muSession.Unlock()
}

func (mgr *PolicyBaseAuth) Clean() {
	now := time.Now()
	mgr.muSession.Lock()
	for key, session := range mgr.sessions {
		if atomic.LoadUint64(&session.active) > 0 {
			continue
		}
		session.muS.Lock()
		if session.lastseen.Add(120 * time.Minute).Before(now) {
			delete(mgr.sessions, key)
			zlog.Info().
				Str("type", "auth/logout").
				Str("reason", "inactive").
				Str("user", session.username).
				Str("session", key).
				Msg("")
		}
		session.muS.Unlock()
	}
	mgr.muSession.Unlock()
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

func randString(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
