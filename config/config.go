package config

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database struct {
		Type string `yaml:"type"`

		SQLite struct {
			Path string `yaml:"path"`
		} `yaml:"sqlite"`

		MySQL struct {
			Host     string `yaml:"host"`
			Port     string `yaml:"port"`
			User     string `yaml:"username"`
			Password string `yaml:"password"`
			Name     string `yaml:"name"`
		} `yaml:"mysql"`

		MaxOpenConnections int `yaml:"max-open-connections"`
		MaxIdleConnections int `yaml:"max-idle-connections"`
	} `yaml:"database"`

	Network struct {
		Monitor struct {
			Interface string `yaml:"interface"`
		} `yaml:"monitor"`
	} `yaml:"network"`
}

var config *Config

// NewConfig returns a new decoded Config struct
func newConfig(configPath string) (*Config, error) {
	// Create newConfig structure
	newConfig := &Config{}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&newConfig); err != nil {
		return nil, err
	}

	return newConfig, nil
}

// ValidateConfigPath just makes sure, that the path provided is a file,
// that can be read
func validateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}
	return nil
}

// ParseFlags will create and parse the CLI flags
// and return the path to be used elsewhere
func parseFlags() (string, error) {
	// String that contains the configured configuration path
	var configPath string

	// Set up a CLI flag called "-config" to allow users
	// to supply the configuration file
	flag.StringVar(&configPath, "config", "./config.yaml", "path to config file")

	// Actually parse the flags
	flag.Parse()

	// Validate the path first
	if err := validateConfigPath(configPath); err != nil {
		return "", err
	}

	// Return the configuration path
	return configPath, nil
}

func Init() {
	// Parse the flags from the CLI
	configPath, err := parseFlags()
	if err != nil {
		panic(err)
	}

	// Load the configuration file
	config, err = newConfig(configPath)
	if err != nil {
		panic(err)
	}
}

func GetConfig() *Config {
	return config
}
