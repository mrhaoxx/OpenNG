package net

import "net/url"

type URL struct {
	Underlying Interface

	Interface string
	url.URL
}
