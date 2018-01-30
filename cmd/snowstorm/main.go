package snowstorm

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/golang/glog"
)

var (
	flakes = map[string]Flake{}
	fMutex sync.RWMutex

	// numWorkers is how much parallel we want to be
	numWorkers = 8

	// interval is how often we run the scrubbing name
	interval = 60 * time.Minute

	// minFlakeJobFailures is the minimum number of failures required to consider the
	// test failure as a 'flake'
	minFlakeJobFailures = 2

	// config lists the job names we want to scape and the depth (
	// number of pages) we want to go back when listing builds.
	config = map[string]int{
		"test_branch_origin_extended_conformance_install":        5,
		"test_branch_origin_extended_conformance_install_update": 5,
		"test_branch_origin_extended_conformance_gce":            5,
		"test_pull_request_origin_unit":                          5,
		"test_branch_request_origin_integration":                 5,
		"test_branch_request_origin_cmd":                         5,
		"test_branch_request_origin_end_to_end":                  5,
	}
)

// FlakeSerializable is serializable version of the 'flake'
type FlakeSerializable struct {
	// JobName is the name of the name (eg. _unit, _integration, etc.)
	JobName string `json:"jobName"`
	// Message is the failure message
	Message string `json:"message"`
	// FirstFailure is when we observed this failure for the first time
	FirstFailure time.Time `json:"firstFailure"`
	// LastFailure is the last time we observed this failure
	LastFailure time.Time `json:"lastFailure"`
	// FailedJobs is a list of jobs where this failure was observed
	FailedJobs []string `json:"failedJobs"`
	// FailedJobsCount is total count of FailedJobs
	FailedJobsCount int `json:"failedJobsCount"`
	// LastFailureUrl points to last failed name URL
	LastFailureUrl string `json:"lastFailureUrl"`
}

// FlakesSerializable is serializable version of list of flakes.
type FlakesSerializable struct {
	Count       int                 `json:"count"`
	Items       []FlakeSerializable `json:"items"`
	LastUpdated time.Time           `json:"lastUpdated"`
}

// Job represents an instance of the jenkins job.
type Job struct {
	// Jenkins job name
	name        string
	buildNumber string
	url         string
}

// Exists checks if the job is already recorded as a flake.
func (b Job) Exists() bool {
	defer fMutex.RUnlock()
	fMutex.RLock()
	for _, flake := range flakes {
		if flake.HasJob(b.buildNumber) {
			return true
		}
	}
	return false
}

// BuildFailure represents a single build failure (test case failure)
type BuildFailure struct {
	message   string
	timestamp time.Time
	build     Job
}

// Hash generates a unique hash for the failure error messages (test case name)
func (f BuildFailure) Hash() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(f.message)))
}

// Record records the failure into flakes
func (f BuildFailure) Record() {
	defer fMutex.Unlock()
	fMutex.Lock()
	flake, exists := flakes[f.Hash()]
	// no-op, we already track this flake
	if exists && flake.HasJob(f.build.buildNumber) {
		return
	}
	// we tracking this flake, this is a new failure
	if exists {
		flake.failures[f.build.buildNumber] = f
		if f.timestamp.After(flake.lastFailedAt) {
			flake.lastFailedAt = f.timestamp
		}
		if f.timestamp.Before(flake.firstFailedAt) {
			flake.firstFailedAt = f.timestamp
		}
		flakes[f.Hash()] = flake
		return
	}
	// new flake
	flakes[f.Hash()] = Flake{
		failures:      map[string]BuildFailure{f.build.buildNumber: f},
		lastFailedAt:  f.timestamp,
		firstFailedAt: f.timestamp,
	}
}

// Flake group same failures and records last and first time of their occurrences.
type Flake struct {
	// a map of buildIDs and failures
	failures      map[string]BuildFailure
	lastFailedAt  time.Time
	firstFailedAt time.Time
}

// HasJob checks if the flake already have the job recorded.
func (f Flake) HasJob(jobID string) bool {
	_, exists := f.failures[jobID]
	return exists
}

// unixToTime converts unix epoch to *time.Time or nil of something goes wrong
func unixToTime(s string) *time.Time {
	timeInt, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	t := time.Unix(timeInt, 0)
	return &t
}

func GetBuildFailedTests(b Job) ([]BuildFailure, error) {
	doc, err := goquery.NewDocument(b.url)
	if err != nil {
		return nil, err
	}
	meta := doc.Find(".build-meta").First()
	timeEpoch, found := meta.Find(".timestamp").Attr("data-epoch")
	if !found {
		return nil, fmt.Errorf("unable to find metadata timestamp")
	}
	timestamp := unixToTime(strings.TrimSpace(timeEpoch))
	if timestamp == nil {
		return nil, fmt.Errorf("unable to get timestamp")
	}
	var failures []BuildFailure
	doc.Find("#failures h3 a").Each(func(i int, s *goquery.Selection) {
		s.ChildrenFiltered(".time").Remove()
		failures = append(failures, BuildFailure{
			message:   strings.TrimSpace(s.Text()),
			build:     b,
			timestamp: *timestamp,
		})
	})
	return failures, nil
}

func GetJobBuilds(jobName string) ([]Job, string, error) {
	// TODO: make this generic?
	baseUrl := "https://openshift-gce-devel.appspot.com"
	buildListUrl := strings.Join([]string{baseUrl, "builds/origin-ci-test/logs", jobName}, "/")
	doc, err := goquery.NewDocument(buildListUrl)
	if err != nil {
		return nil, "", err
	}
	jobNameParts := strings.Split(jobName, "?")
	var builds []Job
	doc.Find(".build-number").Each(func(i int, s *goquery.Selection) {
		link, found := s.Parent().Attr("href")
		if !found || !s.Parent().ChildrenFiltered("span").HasClass("build-failure") {
			return
		}
		b := Job{
			buildNumber: strings.TrimSpace(s.Text()),
			name:        jobNameParts[0],
			url:         baseUrl + "/" + link,
		}
		if b.Exists() {
			return
		}
		builds = append(builds, b)
	})
	if len(builds) == 0 {
		return builds, "", nil
	}
	return builds, builds[len(builds)-1].buildNumber, nil
}

func serializeFlakes() ([]byte, error) {
	defer fMutex.RUnlock()
	result := FlakesSerializable{
		Count:       len(flakes),
		LastUpdated: time.Now(),
		Items:       []FlakeSerializable{},
	}
	fMutex.RLock()
	for _, flake := range flakes {
		var (
			lastFailure BuildFailure
			builds      []string
		)
		for _, failure := range flake.failures {
			if failure.timestamp.After(lastFailure.timestamp) {
				lastFailure = failure
			}
			builds = append(builds, failure.build.buildNumber)
		}
		f := FlakeSerializable{
			JobName:         lastFailure.build.name,
			Message:         lastFailure.message,
			FirstFailure:    flake.firstFailedAt,
			LastFailure:     flake.lastFailedAt,
			FailedJobs:      builds,
			FailedJobsCount: len(builds),
			LastFailureUrl:  lastFailure.build.url,
		}
		// Only serialize flakes with more than 1 occurence
		if len(f.FailedJobs) > minFlakeJobFailures {
			result.Items = append(result.Items, f)
		}
	}
	return json.Marshal(&result)
}

func getFlakesForJob(name string, depth int) error {
	var (
		builds []Job
		lastID string
		err    error
	)

	glog.Infof("name %q started", name)
	now := time.Now()

	for i := 1; i <= depth; i++ {
		var newBuilds []Job
		newBuilds, lastID, err = GetJobBuilds(name + lastID)
		if err != nil {
			return err
		}
		lastID = "?before=" + lastID
		builds = append(builds, newBuilds...)
	}

	if len(builds) == 0 {
		glog.Infof("no new builds ...")
		return nil
	}

	buildJobs := make(chan Job)
	wg := &sync.WaitGroup{}
	wg.Add(numWorkers)
	for i := 1; i <= numWorkers; i++ {
		go func() {
			defer wg.Done()
			for b := range buildJobs {
				failures, err := GetBuildFailedTests(b)
				if err != nil {
					glog.Errorf("unable to get tests for name: %v", err)
				}
				for _, f := range failures {
					f.Record()
				}
			}
		}()
	}

	for _, build := range builds {
		buildJobs <- build
	}
	close(buildJobs)
	wg.Wait()
	glog.Infof("name %q finished (took %s)", name, time.Since(now))
	return nil
}

func main() {
	flag.Parse()

	go func() {
		for {
			for jobName, depth := range config {
				if err := getFlakesForJob(jobName, depth); err != nil {
					glog.Errorf("error running name: %v", err)
				}
			}
			time.Sleep(interval)
		}
	}()

	flakeHandler := func(w http.ResponseWriter, r *http.Request) {
		out, err := serializeFlakes()
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("internal error: %v", err)))
		}
		w.WriteHeader(200)
		w.Write(out)
	}

	// Start server
	mux := http.NewServeMux()
	mux.HandleFunc("/flakes.json", flakeHandler)
	addr := "0.0.0.0:8080"
	glog.Infof("Listening on %s ...", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		glog.Fatalf("ERROR: %v", err)
	}
}
