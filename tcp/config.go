package tcp

import (
	"errors"

	"github.com/mrhaoxx/OpenNG/logging"
)

type ControllerConfig struct {
	AddressBindings []string `yaml:"AddressBindings"`

	Binds map[string][]string `yaml:"Binds,flow"`
}
type ProxierConfig struct {
	Routes []Route `yaml:"Routes,flow"`
}
type Route struct {
	Name     string `yaml:"Name"`
	Protocol string `yaml:"Protocol"`
	Backend  string `yaml:"Backend"`
}

type Config struct {
	Controller ControllerConfig `yaml:"Controller"`
	Proxier    ProxierConfig    `yaml:"Proxier"`
}

// func (ctl *Controller) bind(protocol string, services []string) error {
// 	ctl.muConfig.Lock()
// 	defer ctl.muConfig.Unlock()
// 	var bindings []SericeBinding
// 	for _, g := range services {
// 		s, ok := ctl.Services[g]
// 		if !ok {
// 			return errors.New("service " + g + " not found")
// 		}
// 		bindings = append(bindings, SericeBinding{
// 			name:           g,
// 			ServiceHandler: s,
// 		})
// 	}
// 	ctl.Binds[protocol] = bindings
// 	return nil
// }

// func (ctl *Controller) Unbind(protocol string) {
// 	ctl.muConfig.Lock()
// 	defer ctl.muConfig.Unlock()
// 	delete(ctl.Binds, protocol)
// }

func (ctl *Controller) InitAndLoad(cfg ControllerConfig) error {
	ctl.activeConnections = make(map[uint64]*Conn)

	for protocol, bindings := range cfg.Binds {
		logging.Println("sys", "tcp", "Services Bindings", protocol, "->", bindings)
		ctl.Bind(protocol, bindings)
	}
	var es []error
	for _, bds := range cfg.AddressBindings {
		logging.Println("sys", "tcp", "Listening on", bds)
		if err := ctl.Listen(bds); err != nil {
			es = append(es, err)
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

func (prox *tcpproxy) Load(cfg ProxierConfig, clear bool) error {
	if clear {
		prox.Reset()
	}
	for _, e := range cfg.Routes {
		logging.Println("sys", "tcpproxy", e.Name, e.Protocol, "->", e.Backend)

		if err := prox.Add(e.Name, e.Backend, e.Protocol); err != nil {
			return nil
		}
	}
	return nil
}
