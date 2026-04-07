package ui

import (
	ng "github.com/mrhaoxx/OpenNG"
	"github.com/mrhaoxx/OpenNG/modules/log"
	"github.com/mrhaoxx/OpenNG/modules/nghttp"
)

func init() {
	ng.RegisterFunc("webui", func(struct{}) (nghttp.Service, error) {
		log.Loggers.Add(Sselogger)
		return &UI{}, nil
	})
}
