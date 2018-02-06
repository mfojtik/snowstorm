package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/PuerkitoBio/goquery"
	"github.com/golang/glog"
	"google.golang.org/api/option"

	"github.com/mfojtik/snowstorm/cmd/snowstorm/types"
)

var (
	flakes = map[string]Flake{}
	fMutex sync.RWMutex
	config *types.Config
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

func GetBuildFailedTests(b Job, gcsBucket *storage.BucketHandle) ([]BuildFailure, error) {
	glog.Infof("Getting failed tests for %s %s", b.name, b.buildNumber)
	ctx := context.Background()
	gcsPrefix := b.url[strings.Index(b.url, config.BucketName)+len(config.BucketName)+1:]
	jobFiles := gcsBucket.Objects(ctx, &storage.Query{Prefix: gcsPrefix})
	var xmlFiles []*storage.ObjectAttrs
	for {
		object, done := jobFiles.Next()
		if done != nil {
			break
		}
		if strings.HasSuffix(object.Name, ".xml") {
			xmlFiles = append(xmlFiles, object)
		}
	}

	var failures []*types.TestCase
	for _, xmlFile := range xmlFiles {
		xmlReader, err := gcsBucket.Object(xmlFile.Name).NewReader(ctx)
		if err != nil {
			// this should not happen
			glog.Warningf("XML file did not exist when read: %v", err)
			continue
		}

		var suites []*types.TestSuite
		var testSuites types.TestSuites
		if err := xml.NewDecoder(xmlReader).Decode(&testSuites); err != nil {
			xmlReader.Close()
			// Need to re-open the reader to try to parse it again
			xmlReader, err = gcsBucket.Object(xmlFile.Name).NewReader(ctx)
			if err != nil {
				// this should not happen
				glog.Warningf("XML file did not exist when read: %v", err)
				continue
			}
			var testSuite types.TestSuite
			if err := xml.NewDecoder(xmlReader).Decode(&testSuite); err != nil {
				// not all XML is jUnit and that is ok
				xmlReader.Close()
				glog.Warningf("Could not parse XML file %s as jUnit: %v", xmlFile.Name, err)
				continue
			}
			xmlReader.Close()
			suites = append(suites, &testSuite)
		} else {
			suites = append(suites, testSuites.Suites...)
		}
		for _, testSuite := range suites {
			failures = append(failures, accumulateFailures(testSuite)...)
		}
	}

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

	var buildFailures []BuildFailure
	for _, failure := range failures {
		buildFailures = append(buildFailures, BuildFailure{
			message:   failure.Name,
			timestamp: *timestamp,
			build:     b,
		})
	}
	glog.Infof("Found %d failed tests for %s %s", len(buildFailures), b.name, b.buildNumber)
	return buildFailures, nil
}

func accumulateFailures(testSuite *types.TestSuite) []*types.TestCase {
	var failures []*types.TestCase
	for _, testCase := range testSuite.TestCases {
		if testCase.FailureOutput != nil {
			failures = append(failures, testCase)
		}
	}

	for _, childSuite := range testSuite.Children {
		failures = append(failures, accumulateFailures(childSuite)...)
	}
	return failures
}

func GetJobBuilds(jobName string) ([]Job, string, error) {
	// TODO: make this generic?
	baseUrl := "https://openshift-gce-devel.appspot.com"
	buildListUrl := strings.Join([]string{
		baseUrl,
		"builds/origin-ci-test/pr-logs/directory",
		jobName,
	}, "/")
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

type ByCount []FlakeSerializable

func (a ByCount) Len() int           { return len(a) }
func (a ByCount) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByCount) Less(i, j int) bool { return a[i].FailedJobsCount < a[j].FailedJobsCount }

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
		if time.Since(lastFailure.timestamp).Hours() > float64(config.SkipFlakeAfterHours) {
			continue
		}
		if len(builds) < config.MinimumFlakeCount {
			continue
		}
		result.Items = append(result.Items, FlakeSerializable{
			JobName:         lastFailure.build.name,
			Message:         lastFailure.message,
			FirstFailure:    flake.firstFailedAt,
			LastFailure:     lastFailure.timestamp,
			FailedJobs:      builds,
			FailedJobsCount: len(builds),
			LastFailureUrl:  lastFailure.build.url,
		})
	}
	sort.Sort(ByCount(result.Items))
	return json.Marshal(&result)
}

func getFlakesForJob(name string, depth int, gcsBucket *storage.BucketHandle) error {
	var (
		builds []Job
		lastID string
		err    error
	)

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
	wg.Add(config.WorkerCount)
	for i := 1; i <= config.WorkerCount; i++ {
		go func() {
			defer wg.Done()
			for b := range buildJobs {
				failures, err := GetBuildFailedTests(b, gcsBucket)
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
	glog.Infof("name %q finished (elapsed %s)", name, time.Since(now))
	return nil
}

func Usage() {
	fmt.Fprintf(os.Stderr, `
Usage: %s [-config <string>]
`, os.Args[0])
	flag.PrintDefaults()
}

func main() {
	configPath := flag.String("config", "", "a path to a config file to use")
	staticPathFlag := flag.String("static-path", "/static", "override the directory with HTML files")
	flag.Usage = Usage
	flag.Parse()

	var err error
	config, err = types.ParseConfig(*configPath)
	if err != nil {
		glog.Fatalf("error reading config %q: %v", *configPath, err)
	}

	staticPath := ""
	if *staticPathFlag != "" {
		staticPath = *staticPathFlag
	}

	ctx := context.Background()
	gcsClient, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		glog.Fatalf("Could not connect to GCS: %v", err)
	}
	gcsBucket := gcsClient.Bucket(config.BucketName)

	go func() {
		for {
			for _, job := range config.Jobs {
				if err := getFlakesForJob(job.Name, config.Depth, gcsBucket); err != nil {
					glog.Errorf("error running name: %v", err)
				}
			}
			time.Sleep(time.Duration(config.IntervalSeconds) * time.Second)
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
	mux.Handle("/", http.FileServer(http.Dir(staticPath)))

	addr := "0.0.0.0:8080"
	glog.Infof("Listening on %s ...", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		glog.Fatalf("ERROR: %v", err)
	}
}
