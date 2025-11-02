package netgate

import (
	_ "embed"
)

//go:embed NetGATE.svg
var logo_svg []byte

func Logo() []byte {
	return logo_svg
}
