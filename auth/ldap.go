package auth

type ldapAuth struct {
	url        string
	searchBase string

	bindDN string
	bindPW string
}

