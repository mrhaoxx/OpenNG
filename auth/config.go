package auth

import (
	"errors"

	logging "github.com/haoxingxing/OpenNG/logging"
)

type Config struct {
	Users    []User   `yaml:"Users,flow"`
	Policies []Policy `yaml:"Policies,flow"`
}
type User struct {
	Username     string `yaml:"Username"`
	PasswordHash string `yaml:"PasswordHash"`
}
type Policy struct {
	Name      string   `yaml:"Name"`
	Allowance bool     `yaml:"Allowance"`
	Users     []string `yaml:"Users,flow"`
	Hosts     []string `yaml:"Hosts,flow"`
	Paths     []string `yaml:"Paths,flow"`
}

func (LGM *policyBaseAuth) Load(cfg Config) error {

	for _, u := range cfg.Users {
		logging.Println("sys", "auth", "Found User", u.Username)
		LGM.SetUser(u.Username, u.PasswordHash)
	}
	var es []error
	for _, p := range cfg.Policies {
		if t := LGM.AddPolicy(p.Name, p.Allowance, p.Users, p.Hosts, p.Paths); t != nil {
			logging.Println("sys", "auth", "Found Policy", p.Name)
			es = append(es, t)
		}
	}

	if es != nil {
		errs := "While loading cfg:\n"
		for _, e := range es {
			errs += e.Error() + "\n"
		}
		return errors.New(errs)
	} else {
		return nil
	}

}
func (LGM *policyBaseAuth) SetUser(username string, passwordhash string) {
	LGM.usrs[username] = &user{
		name:         username,
		passwordHash: passwordhash,
	}
}
