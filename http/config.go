package http

import "github.com/haoxingxing/OpenNG/logging"

type Config struct {
	Midware MidwareConfig `yaml:"Midware"`
	Proxier ProxierConfig `yaml:"Proxier"`
}
type MidwareConfig struct {
	Binds []ServiceBind `yaml:"Binds,flow"`
}

type ServiceBind struct {
	Name  string   `yaml:"Name"`
	Id    string   `yaml:"Id"`
	Hosts []string `yaml:"Hosts"`
}
type ProxierConfig struct {
	Hosts []ProxyHost `yaml:"Hosts,flow"`
}
type ProxyHost struct {
	Name          string   `yaml:"Name"`
	Hosts         []string `yaml:"Hosts"`
	Backend       string   `yaml:"Backend"`
	TlsSkipVerify bool     `yaml:"TlsSkipVerify"`
}

func (hmw *Midware) Load(cfg MidwareConfig) error {

	for _, bind := range cfg.Binds {
		logging.Println("sys", "http", "Binding", bind.Id)

		hmw.Bind(bind.Id, bind.Name, bind.Hosts)
	}
	return nil
}

func (prox *httpproxy) Load(cfg ProxierConfig, clear bool) error {
	if clear {
		prox.Reset()
	}
	for _, host := range cfg.Hosts {
		if err := prox.Add(host.Name, host.Hosts, host.Backend, 0, host.TlsSkipVerify); err != nil {
			return err
		}
	}
	return nil
}
