package auth

import "github.com/dlclark/regexp2"

const PrefixAuth = "/auth"

const PrefixAuthPolicy string = "/pb"
const verfiyCookieKey string = "_ng_s"

var regexpforit = regexp2.MustCompile("^"+PrefixAuth+PrefixAuthPolicy+"/.*$", 0)

var regexpforauthpath = []*regexp2.Regexp{regexpforit}
