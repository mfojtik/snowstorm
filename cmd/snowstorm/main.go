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
)

var (
	flakes = map[string]Flake{}
	fMutex sync.RWMutex

	// numWorkers is how much parallel we want to be
	numWorkers = 8

	// interval is how often we run the scrubbing name
	interval = 1800 * time.Second

	// minFlakeJobFailures is the minimum number of failures required to consider the
	// test failure as a 'flake'
	minFlakeJobFailures = 2

	// config lists the job names we want to scape and the depth (
	// number of pages) we want to go back when listing builds.
	// TODO: Make this config
	config = map[string]int{
		"test_pull_request_origin_integration":                         5,
		"test_pull_request_origin_unit":                                5,
		"test_pull_request_origin_end_to_end":                          5,
		"test_pull_request_origin_cmd":                                 5,
		"test_pull_request_origin_extended_conformance_gce":            5,
		"test_pull_request_origin_extended_conformance_install":        5,
		"test_pull_request_origin_extended_conformance_install_update": 5,
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

// The below types are directly marshalled into XML. The types correspond to jUnit
// XML schema, but do not contain all valid fields. For instance, the class name
// field for test cases is omitted, as this concept does not directly apply to Go.
// For XML specifications see http://help.catchsoftware.com/display/ET/JUnit+Format
// or view the XSD included in this package as 'junit.xsd'

// TestSuites represents a flat collection of jUnit test suites.
type TestSuites struct {
	XMLName xml.Name `xml:"testsuites"`

	// Suites are the jUnit test suites held in this collection
	Suites []*TestSuite `xml:"testsuite"`
}

// TestSuite represents a single jUnit test suite, potentially holding child suites.
type TestSuite struct {
	XMLName xml.Name `xml:"testsuite"`

	// Name is the name of the test suite
	Name string `xml:"name,attr"`

	// NumTests records the number of tests in the TestSuite
	NumTests uint `xml:"tests,attr"`

	// NumSkipped records the number of skipped tests in the suite
	NumSkipped uint `xml:"skipped,attr"`

	// NumFailed records the number of failed tests in the suite
	NumFailed uint `xml:"failures,attr"`

	// Duration is the time taken in seconds to run all tests in the suite
	Duration float64 `xml:"time,attr"`

	// Properties holds other properties of the test suite as a mapping of name to value
	Properties []*TestSuiteProperty `xml:"properties,omitempty"`

	// TestCases are the test cases contained in the test suite
	TestCases []*TestCase `xml:"testcase"`

	// Children holds nested test suites
	Children []*TestSuite `xml:"testsuite"`
}

// TestSuiteProperty contains a mapping of a property name to a value
type TestSuiteProperty struct {
	XMLName xml.Name `xml:"property"`

	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// TestCase represents a jUnit test case
type TestCase struct {
	XMLName xml.Name `xml:"testcase"`

	// Name is the name of the test case
	Name string `xml:"name,attr"`

	// Classname is an attribute set by the package type and is required
	Classname string `xml:"classname,attr,omitempty"`

	// Duration is the time taken in seconds to run the test
	Duration float64 `xml:"time,attr"`

	// SkipMessage holds the reason why the test was skipped
	SkipMessage *SkipMessage `xml:"skipped"`

	// FailureOutput holds the output from a failing test
	FailureOutput *FailureOutput `xml:"failure"`

	// SystemOut is output written to stdout during the execution of this test case
	SystemOut string `xml:"system-out,omitempty"`

	// SystemErr is output written to stderr during the execution of this test case
	SystemErr string `xml:"system-err,omitempty"`
}

// SkipMessage holds a message explaining why a test was skipped
type SkipMessage struct {
	XMLName xml.Name `xml:"skipped"`

	// Message explains why the test was skipped
	Message string `xml:"message,attr,omitempty"`
}

// FailureOutput holds the output from a failing test
type FailureOutput struct {
	XMLName xml.Name `xml:"failure"`

	// Message holds the failure message from the test
	Message string `xml:"message,attr"`

	// Output holds verbose failure output from the test
	Output string `xml:",chardata"`
}

func GetBuildFailedTests(b Job, gcsBucket *storage.BucketHandle) ([]BuildFailure, error) {
	glog.Infof("Getting failed tests for %s %s", b.name, b.buildNumber)
	ctx := context.Background()
	attributes, err := gcsBucket.Attrs(ctx)
	if err != nil {
		return []BuildFailure{}, fmt.Errorf("could not get GCS bucket name: %v", err)
	}
	// we strip out the Gubernator prefix from the url to get the GCS path
	gcsPrefix := b.url[strings.Index(b.url, attributes.Name) + len(attributes.Name) + 1:]
	glog.Infof("Listing XML files for %s %s using prefix %s", b.name, b.buildNumber, gcsPrefix)
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

	var failures []*TestCase
	for _, xmlFile := range xmlFiles {
		xmlReader, err := gcsBucket.Object(xmlFile.Name).NewReader(ctx)
		if err != nil {
			// this should not happen
			glog.Warningf("XML file did not exist when read: %v", err)
			continue
		}
		var testSuites TestSuites
		if err := xml.NewDecoder(xmlReader).Decode(&testSuites); err != nil {
			// not all XML is jUnit and that is ok
			glog.Warningf("Could not parse XML file %s as jUnit: %v", xmlFile.Name, err)
			continue
		}

		glog.Infof("Considering %s as jUnit XML for %s %s", xmlFile.Name, b.name, b.buildNumber)
		for _, testSuite := range testSuites.Suites {
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

func accumulateFailures(testSuite *TestSuite) []*TestCase {
	var failures []*TestCase
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
	glog.Infof("Getting builds for job %s", jobName)
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
	sort.Sort(ByCount(result.Items))
	return json.Marshal(&result)
}

func getFlakesForJob(name string, depth int, gcsBucket *storage.BucketHandle) error {
	glog.Infof("Finding flakes for job %s", name)
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
	glog.Infof("name %q finished (took %s)", name, time.Since(now))
	return nil
}

func Usage() {
	fmt.Fprintf(os.Stderr, `
Usage: %s [-interval <sec>] [-workers <sec>] [-min-flake-failures <sec>]
`, os.Args[0])
	flag.PrintDefaults()
}

func main() {
	minFlakeFailuresFlag := flag.Uint("min-flake-failures", 2, "minumum failures to consider a flake")
	intervalFlag := flag.Uint("interval", 3600, "interval in seconds to run scrapper")
	workersFlag := flag.Uint("workers", 8, "interval in seconds to run scrapper")

	flag.Usage = Usage
	flag.Parse()

	if minFlakeFailuresFlag != nil {
		minFlakeJobFailures = int(*minFlakeFailuresFlag)
	}
	if intervalFlag != nil {
		interval = time.Second * time.Duration(*intervalFlag)
	}
	if workersFlag != nil {
		numWorkers = int(*workersFlag)
	}

	ctx := context.Background()
	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		glog.Fatalf("Could not connect to GCS: %v", err)
	}
	gcsBucket := gcsClient.Bucket("origin-ci-test")

	go func() {
		for {
			for jobName, depth := range config {
				if err := getFlakesForJob(jobName, depth, gcsBucket); err != nil {
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
	mux.Handle("/", http.FileServer(http.Dir("/static")))

	addr := "0.0.0.0:8080"
	glog.Infof("Listening on %s ...", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		glog.Fatalf("ERROR: %v", err)
	}
}
