package trojan

import (
	"crypto/sha256"
	"encoding/hex"

	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/pkg/ngnet"
)

type TrojanConfig struct {
	Passwords []string        `ng:"passwords"`
	Interface ngnet.Interface `ng:"interface" default:"sys"`
}

func NewTrojanServer(cfg TrojanConfig) (*Server, error) {
	hashes := make([]string, len(cfg.Passwords))
	for i, pw := range cfg.Passwords {
		sum := sha256.Sum224([]byte(pw))
		hashes[i] = hex.EncodeToString(sum[:])
	}
	return &Server{
		PasswordHashes: hashes,
		Underlying:     cfg.Interface,
	}, nil
}

func init() {
	ng.RegisterFunc("trojan::server", NewTrojanServer)
}
