package logging

import (
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/api/write"
)

type influxLogger struct {
	client influxdb2.Client
	write  api.WriteAPI

	tags map[string]string
}

func (I *influxLogger) Write(byt []byte) (int, error) {
	I.write.WritePoint(write.NewPoint("ng", I.tags, map[string]interface{}{
		"message": byt,
	}, time.Now()))
	return 0, nil
}

func NewInfluxLogger(cfg InfluxConfig) *influxLogger {
	client := influxdb2.NewClient(cfg.Url, cfg.Token)
	return &influxLogger{
		client: client,
		write:  client.WriteAPI(cfg.Org, cfg.Bucket),
	}
}

type InfluxConfig struct {
	Url    string `yaml:"URL"`
	Token  string `yaml:"Token"`
	Org    string `yaml:"Org"`
	Bucket string `yaml:"Bucket"`
}
