package tls

import (
	logging "github.com/haoxingxing/OpenNG/logging"
)

type Config struct {
	Certificates  []Certificate `yaml:"Certificates,flow"`
	MinTLSVersion int           `yaml:"MinTLSVersion"`
}

type Certificate struct {
	CertFile string `yaml:"CertFile"`
	KeyFile  string `yaml:"KeyFile"`
}

func (mgr *tlsMgr) Load(cfg Config) {
	for _, c := range cfg.Certificates {
		logging.Println("sys", "tls", "Found certificate", c.CertFile)

		mgr.LoadCertificate(c.CertFile, c.KeyFile)
	}
}

// var watcher *fsnotify.Watcher

// var certwatchlist map[string]string = make(map[string]string)

// // func init() {
// 	var err error
// 	watcher, err = fsnotify.NewWatcher()
// 	if err != nil {
// 		logging.Println("sys", "Can't start watcher to files", err)
// 	}

// 	go func() {
// 		for {
// 			select {
// 			case e, ok := <-watcher.Events:
// 				if !ok {
// 					return
// 				}
// 				logging.Println("sys", "Certificate "+e.Name+" modified.")
// 				time.Sleep(300 * time.Second)
// 				LoadCertificate(e.Name, certwatchlist[e.Name], false)

// 			case err, ok := <-watcher.Errors:
// 				if !ok {
// 					return
// 				}
// 				logging.Println("sys", "[WATCH] Err ", err)
// 			}
// 		}
// 	}()

// }
