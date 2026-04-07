package wireguard

import (
	"encoding/base64"
	"fmt"
)

func b64tohex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}
