package config

import (
	"gopkg.in/yaml.v2"
	"os"
)

type Rule struct {
	From         string   `yaml:"from"`
	To           string   `yaml:"to"`
	AuthRequired bool     `yaml:"auth_required"`
	Roles        []string `yaml:"roles"`
}

type Config struct {
	Rules []Rule `yaml:"rules"`
}

func ReadConfig(filename string) (*Config, error) {
	file, err := os.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	var config Config

	err = yaml.Unmarshal(file, &config)

	if err != nil {
		return nil, err
	}

	return &config, nil
}
