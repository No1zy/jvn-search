package parser

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

type Config struct {
	Product []string `yaml:"product"`
}

func CreateConfig() (config *Config, err error) {
	data, err := ioutil.ReadFile("config.yml")
	if err != nil {
		log.Fatal(err)
	}
	yaml.Unmarshal(data, &config)
	return
}
