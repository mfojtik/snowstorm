package types

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type SourceJob struct {
	Name string
}

type Config struct {
	// BucketName is name of the GCS bucket to use
	BucketName string `yaml:"bucket-name"`

	// MinimumFlakeCount is a count of failures to occur before we consider the failure as a flake.
	MinimumFlakeCount int `yaml:"min-flake-count"`

	// SkipFlakeAfterHours is number of hours that has to pass after last observation of the flake
	// to remove the flake from the list.
	SkipFlakeAfterHours int `yaml:"skip-flake-after-hours"`

	// WorkerCount is number of workers we want to run to crawl the Gubernator. Higher number increase
	// the concurrency but might break Gubernator ;-)
	WorkerCount int `yaml:"worker-count"`

	// IntervalSeconds is number of seconds to wait between scaping the gubernator for new builds.
	IntervalSeconds int `yaml:"interval-seconds"`

	// Depth is number of pages to process in gubernator build view
	Depth int `yaml:"depth"`

	// Jobs is a list of jobs to scape
	Jobs []SourceJob `yaml:"source-jobs"`
}

func ParseConfig(path string) (*Config, error) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := Config{}
	err = yaml.Unmarshal(configBytes, &result)
	if err != nil {
		return nil, err
	}
	return &result, err
}
