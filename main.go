package main

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

	numWorkers = 8
	interval   = 60 * time.Minute
)

type FlakeSerializable struct {
	ID             string    `json:"id"`
	JobName        string    `json:"jobName"`
	Message        string    `json:"message"`
	FirstFailure   time.Time `json:"firstFailure"`
	LastFailure    time.Time `json:"lastFailure"`
	FailedJobs     []string  `json:"failedJobs"`
	LastFailureUrl string    `json:"lastFailureUrl"`
}

type FlakesSerializable struct {
	Count       int                 `json:"count"`
	Items       []FlakeSerializable `json:"items"`
	LastUpdated time.Time           `json:"lastUpdated"`
}

type Build struct {
	job   string
	jobID string
	url   string
}

func (b Build) Exists() bool {
	defer fMutex.RUnlock()
	fMutex.RLock()
	for _, flake := range flakes {
		if flake.HasJob(b.jobID) {
			return true
		}
	}
	return false
}

type Failure struct {
	message   string
	timestamp time.Time
	build     Build
}

func (f Failure) Hash() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(f.message)))
}

func (f Failure) Record() {
	defer fMutex.Unlock()
	fMutex.Lock()
	flake, exists := flakes[f.Hash()]
	// no-op, we already track this flake
	if exists && flake.HasJob(f.build.jobID) {
		return
	}
	// we tracking this flake, this is a new failure
	if exists {
		flake.failures[f.build.jobID] = f
		if f.timestamp.After(flake.lastFailedAt) {
			flake.lastFailedAt = f.timestamp
		}
		if f.timestamp.Before(flake.firstFailedAt) {
			flake.firstFailedAt = f.timestamp
		}
		flakes[f.Hash()] = flake
		return
	}
	// new potential flake
	flakes[f.Hash()] = Flake{
		failures:      map[string]Failure{f.build.jobID: f},
		lastFailedAt:  f.timestamp,
		firstFailedAt: f.timestamp,
	}
}

type Flake struct {
	failures map[string]Failure

	lastFailedAt  time.Time
	firstFailedAt time.Time
}

func (f Flake) HasJob(jobID string) bool {
	_, exists := f.failures[jobID]
	return exists
}

func unixToTime(s string) *time.Time {
	timeInt, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	t := time.Unix(timeInt, 0)
	return &t
}

func GetBuildFailedTests(b Build) ([]Failure, error) {
	doc, err := goquery.NewDocument(b.url)
	if err != nil {
		return nil, err
	}
	meta := doc.Find(".build-meta").First()
	timeEpoch, found := meta.Find(".timestamp").Attr("data-epoch")
	if !found {
		h, _ := meta.Html()
		return nil, fmt.Errorf("unable to find metadata timestamp (%s)", h)
	}
	timestamp := unixToTime(strings.TrimSpace(timeEpoch))
	if timestamp == nil {
		return nil, fmt.Errorf("unable to get timestamp")
	}
	var failures []Failure

	doc.Find("#failures h3 a").Each(func(i int, s *goquery.Selection) {
		s.ChildrenFiltered(".time").Remove()
		failures = append(failures, Failure{
			message:   strings.TrimSpace(s.Text()),
			build:     b,
			timestamp: *timestamp,
		})
	})

	return failures, nil
}

func GetJobBuilds(jobName string) ([]Build, string, error) {
	baseUrl := "https://openshift-gce-devel.appspot.com"
	buildListUrl := strings.Join([]string{baseUrl, "builds/origin-ci-test/logs", jobName}, "/")
	doc, err := goquery.NewDocument(buildListUrl)
	if err != nil {
		return nil, "", err
	}
	jobNameParts := strings.Split(jobName, "?")
	var builds []Build
	doc.Find(".build-number").Each(func(i int, s *goquery.Selection) {
		link, found := s.Parent().Attr("href")
		if !found || !s.Parent().ChildrenFiltered("span").HasClass("build-failure") {
			return
		}
		b := Build{
			jobID: strings.TrimSpace(s.Text()),
			job:   jobNameParts[0],
			url:   baseUrl + "/" + link,
		}
		if b.Exists() {
			return
		}
		builds = append(builds, b)
	})
	if len(builds) == 0 {
		return builds, "", nil
	}
	return builds, builds[len(builds)-1].jobID, nil
}

func serializeFlakes() ([]byte, error) {
	defer fMutex.RUnlock()
	result := FlakesSerializable{
		Count:       len(flakes),
		LastUpdated: time.Now(),
		Items:       []FlakeSerializable{},
	}
	fMutex.RLock()
	for flakeID, flake := range flakes {
		var (
			lastFailure Failure
		)
		var builds []string

		for _, failure := range flake.failures {
			if failure.timestamp.After(lastFailure.timestamp) {
				lastFailure = failure
			}
			builds = append(builds, failure.build.jobID)
		}
		f := FlakeSerializable{
			ID:             flakeID,
			JobName:        lastFailure.build.job,
			Message:        lastFailure.message,
			FirstFailure:   flake.firstFailedAt,
			LastFailure:    flake.lastFailedAt,
			FailedJobs:     builds,
			LastFailureUrl: lastFailure.build.url,
		}
		// Only serialize flakes with more than 1 occurence
		if len(f.FailedJobs) > 1 {
			result.Items = append(result.Items, f)
		}
	}
	return json.Marshal(&result)
}

func getFlakesForJob(name string, depth int) error {
	var (
		builds []Build
		lastID string
		err    error
	)

	glog.Infof("job %q started", name)
	now := time.Now()

	for i := 1; i <= depth; i++ {
		var newBuilds []Build
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

	buildJobs := make(chan Build)
	wg := &sync.WaitGroup{}
	wg.Add(numWorkers)
	for i := 1; i <= numWorkers; i++ {
		go func() {
			defer wg.Done()
			for b := range buildJobs {
				failures, err := GetBuildFailedTests(b)
				if err != nil {
					glog.Errorf("unable to get tests for job: %v", err)
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
	glog.Infof("job %q finished (took %s)", name, time.Since(now))
	return nil
}

func main() {
	flag.Parse()

	config := map[string]int{
		"test_branch_origin_extended_conformance_install":        5,
		"test_branch_origin_extended_conformance_install_update": 5,
		"test_branch_origin_extended_conformance_gce":            5,
		"test_pull_request_origin_unit":                          5,
		"test_branch_request_origin_integration":                 5,
		"test_branch_request_origin_cmd":                         5,
		"test_branch_request_origin_end_to_end":                  5,
	}

	go func() {
		for {
			for jobName, depth := range config {
				if err := getFlakesForJob(jobName, depth); err != nil {
					glog.Errorf("error running job: %v", err)
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
