package cloudig

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	awslocal "github.com/Optum/cloudig/pkg/aws"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/sirupsen/logrus"
)

const (
	queryForUsage     string = "QU"
	queryForErrors    string = "QE"
	identityDelimiter string = "@"
	keyIdentityARN    string = "identity_arn"
	keyErrorCode      string = "errorcode"
	keyEventSource    string = "eventsource"
	keyEventName      string = "eventname"
	keyARN            string = "arn"
	keyCount          string = "count"
)

// ReflectReport is struct that contains a slice of Reflect findings
type ReflectReport struct {
	Findings []reflectFinding `json:"findings"`
	Flags    ReflectFlags     `json:"-"` // hide in json output
	jsonOutputHelper
}

type reflectFinding struct {
	AccountID     string          `json:"accountId"`
	Identity      string          `json:"IAMIdentity"`
	AccessDetails []accessDetails `json:"accessDetails"`
	PermissionSet []string        `json:"permissionSet"`
	Comments      string          `json:"comments"`
}

type accessDetails struct {
	Event string `json:"IAMAction"`
	Count int    `json:"UsageCount"`
}

// ReflectFlags provides a collection of different flags for various stages of handling requests
type ReflectFlags struct {
	region              string
	roles               []string
	roleTags            map[string]string
	usageReport         bool
	errorReport         bool
	includeUserIdentity bool
	absoluteTime        string
	relativeTime        int
}

// NewReflectFlags returns a new instance Reflectflag
func NewReflectFlags(region string, roles []string, roleTags map[string]string, usageReport, errorReport, includeIdentity bool, absTime string, relTime int) ReflectFlags {
	return ReflectFlags{
		region:              region,
		roles:               roles,
		roleTags:            roleTags,
		usageReport:         usageReport,
		errorReport:         errorReport,
		includeUserIdentity: includeIdentity,
		absoluteTime:        absTime,
		relativeTime:        relTime,
	}
}

type runQueryResult struct {
	result *athena.ResultSet
	err    error
}

// GetReport retrives the reflect report for a given account
func (report *ReflectReport) GetReport(client awslocal.APIs, comments []Comments) error {
	start := time.Now()
	flags := report.Flags
	accountID, err := client.GetAccountID()
	if err != nil {
		return err
	}
	logrus.Infof("working on reflect report for account: %s", accountID)

	logrus.Infof("getting the s3 prefix associated with the CloudTrail for account: %s", accountID)
	// get S3 bucket with prefix associated with CloudTrail
	s3Prefix, err := client.GetS3LogPrefixForCloudTrail()
	if err != nil {
		return err
	}

	if s3Prefix == nil {
		return fmt.Errorf("Either Cloudtrail is not enabled or doesn't have an S3 bucket associated in account: %s", accountID)
	}

	logrus.Debugf("retrieving the list of AWS regions")
	regionList := make([]string, 0)
	for _, p := range endpoints.DefaultPartitions() {
		for region := range p.Regions() {
			regionList = append(regionList, region)
		}
	}
	// Consistent ordering avoids creating table due to metadata mismatch
	sort.Strings(regionList)

	logrus.Infof("constructing the Athena table metadata form the s3 prefix for account: %s", accountID)
	// construct Athena table metadata from s3 location
	meta := awslocal.NewAthenaTableMetaDataForCloudTrail(aws.StringValue(s3Prefix), regionList)

	// get existing or new table name
	logrus.Infof("finding the existing Athena table from the constructed metadata for account: %s", accountID)
	tableName, err := client.GetTableforMetadata(meta)
	if err != nil {
		logrus.Warnf("error getting the existing valid Athena table from the account %s: %s", accountID, err.Error())
	}
	if tableName == nil {
		logrus.Warnf("could not get valid Athena table from the account %s", accountID)
		logrus.Infof("creating new Athena table in account: %s", accountID)
		tableName, err = client.CreateTableFromMetadata(meta)
		if err != nil {
			logrus.Errorf("error creating Athena table in account: %s : %v", accountID, err)
			return err
		}
	} else {
		logrus.Infof("found the existing Athena table: %s for account: %s", aws.StringValue(tableName), accountID)
	}
	targetedRoles := make([]string, 0)
	// Update roles if roles from Flags are empty but roleTags are provided
	if len(flags.roles) == 0 {
		// if RoleTags are also empty, we do nothing here
		if len(flags.roleTags) > 0 {
			// list all roles with a specific set of tags
			logrus.Infof("getting the roles from tags: %v for account: %s", flags.roleTags, accountID)
			roles, err := client.GetRolesFromTags(flags.roleTags)
			if err != nil {
				logrus.Infof("could not get roles from tags for account: %s : %v", accountID, err)
			} else {
				logrus.Debugf("list of roles from tags %v: %v for account: %s", flags.roleTags, roles, accountID)
				if len(roles) == 0 {
					return fmt.Errorf("no roles found for the given set of tags %v in account: %s", flags.roleTags, accountID)
				}
				targetedRoles = roles
				flags.roles = targetedRoles
			}
		}
	} else {
		targetedRoles = flags.roles
	}

	// polpulate the findings for a given roles
	logrus.Infof("populating findings for roles in account: %s", accountID)
	findings, err := populateFindings(client, aws.StringValue(tableName), flags)
	if err != nil {
		return err
	}
	logrus.Infof("successfully populated the findings for roles in account: %s", accountID)

	permissionForRoles := make(map[string][]string)

	// Populate the actual permissions for the targated roles. targeted roles are the once provided by the user,
	// if none provided, actual permsions are retrived for every role in the findings
	if len(targetedRoles) == 0 {
		for _, v := range findings {
			targetedRoles = append(targetedRoles, strings.Split(v.Identity, identityDelimiter)[0])
		}
	}
	logrus.Debugf("targeted roles are %v", targetedRoles)
	logrus.Infof("finding the actual permission for the roles in account: %s", accountID)
	permissionForRoles = client.GetNetIAMPermissionsForRoles(targetedRoles)

	// loop through all findings to add comments and policy actions
	for k, v := range findings {
		findings[k].AccountID = accountID
		findings[k].PermissionSet = permissionForRoles[strings.Split(v.Identity, identityDelimiter)[0]]
		findings[k].Comments = getComments(comments, accountID, findingTypeReflectIAM, v.Identity)
	}
	report.Findings = append(report.Findings, findings...)
	logrus.Infof("reflecting on account %s took %s", accountID, time.Since(start))
	return nil
}

func populateFindings(client awslocal.APIs, tableName string, flags ReflectFlags) ([]reflectFinding, error) {
	var wg sync.WaitGroup
	findings := make([]reflectFinding, 0)
	output := make(chan runQueryResult, 2)

	if flags.usageReport {
		logrus.Debugf("reflecting on usage report")
		wg.Add(1)
		// Run query - 1
		go func() {
			defer wg.Done()
			resultSetUsage, err := client.RunQuery(tableName, createQueryFromFlags(flags, tableName, queryForUsage))
			output <- runQueryResult{result: resultSetUsage, err: err}
		}()
	}

	if flags.errorReport {
		logrus.Debugf("reflecting on error report")
		wg.Add(1)
		// Run Query - 2
		go func() {
			defer wg.Done()
			resultSetError, err := client.RunQuery(tableName, createQueryFromFlags(flags, tableName, queryForErrors))
			output <- runQueryResult{result: resultSetError, err: err}
		}()
	}

	// lets run this in background to close the chanel once all background routines are complete
	go func() {
		wg.Wait()
		close(output)
	}()

	keys := make([]string, 0)
	dataSlice := make([]string, 0)
	for v := range output {
		if v.err != nil {
			return findings, v.err
		}
		for k, v := range v.result.Rows {
			if k == 0 {
				for _, v1 := range v.Data {
					keys = append(keys, aws.StringValue(v1.VarCharValue))
				}
				continue
			}
			for _, v2 := range v.Data {
				dataSlice = append(dataSlice, aws.StringValue(v2.VarCharValue))
			}
			ide, acc := constructFinding(dataSlice, keys)
			updateFinding(flags, &findings, ide, acc)
			dataSlice = nil
		}
		keys = nil
	}
	return findings, nil
}

// create or update finding
func updateFinding(flags ReflectFlags, findings *[]reflectFinding, identity string, eventD accessDetails) {
	// Filterting of the results come into play only when number of roles are > 1
	// when no roles are provided, all results are returned
	// when a single role is provided , query is designed to return result for single role
	if len(flags.roles) > 1 {
		if !Contains(flags.roles, strings.Split(identity, identityDelimiter)[0]) {
			return
		}
	}

	found := false
	// add to accessDetails if Identity is already in the slice
	for k, v := range *findings {
		if v.Identity == identity {
			for adk, adv := range v.AccessDetails {
				if adv.Event == eventD.Event {
					v.AccessDetails[adk].Count = adv.Count + eventD.Count
					found = true
					return
				}
			}

			(*findings)[k] = reflectFinding{
				Identity:      identity,
				AccessDetails: append(v.AccessDetails, eventD),
			}
			found = true
			break
		}
	}
	// add new finding if identity is not found in the slice
	if !found {
		ed := make([]accessDetails, 0)
		*findings = append(*findings, reflectFinding{
			Identity:      identity,
			AccessDetails: append(ed, eventD),
		})
	}
}

// constructFinding is a helper function that transforms a row of the query output to finding based on row header(keys)
func constructFinding(dataSlice, keys []string) (string, accessDetails) {
	eventD := accessDetails{}
	var identity string
	var hasErrorCode, hasIdentity bool
	indexMap := make(map[string]int)
	for k, v := range keys {
		indexMap[v] = k
		if v == keyIdentityARN {
			hasIdentity = true
		}
		if v == keyErrorCode {
			hasErrorCode = true
		}
	}

	if hasIdentity {
		ss := strings.Split(dataSlice[indexMap[keyIdentityARN]], "/")
		identity = dataSlice[indexMap[keyARN]] + identityDelimiter + ss[len(ss)-1]
	} else {
		identity = dataSlice[indexMap[keyARN]]
	}

	if hasErrorCode {
		eventD.Event = dataSlice[indexMap[keyEventSource]] + "/" + dataSlice[indexMap[keyEventName]] + "/" + dataSlice[indexMap[keyErrorCode]]
	} else {
		eventD.Event = dataSlice[indexMap[keyEventSource]] + "/" + dataSlice[indexMap[keyEventName]]
	}
	count, err := strconv.Atoi(dataSlice[indexMap[keyCount]])
	if err != nil {
		logrus.Errorf("error converting count value from string '%s' to int: %v", dataSlice[indexMap[keyCount]], err)
		eventD.Count = 0
	} else {
		eventD.Count = count
	}
	logrus.Debugf("constructed finding %s -> %v", identity, eventD)
	return identity, eventD
}

type timeRange struct {
	Months         []int
	Days           []int
	Years          []int
	EventTimeRange []string
}

// createQueryFromFlags construct query from given flags and query type
func createQueryFromFlags(flags ReflectFlags, tableName, queryType string) string {
	var timeR timeRange
	//var needIdentity bool
	var role string
	var tpl bytes.Buffer

	// additional identity field is used only if single role is provided
	if len(flags.roles) == 1 {
		role = flags.roles[0]
	} else {
		role = ""
	}

	// First, examine the timeAbolute,If time timeAbolute is provided, timeRelative is ignored
	// format of timeAbolute (mm/dd/yyyy-mm/dd/yyyy) is assumed to be accurate as this should be handled in the CLI validation
	if flags.absoluteTime != "" {
		timeR = constructPartitionDataFromTime(flags.absoluteTime)
		// If time timeAbolute is not provided, timeRelative is used
		// format of timeRelative (day int) is assumed to be accurate as this should be handled in the CLI validation
	} else {
		timeR = constructPartitionDataFromTime(getAbsoluteTime(flags.relativeTime, time.Now()))
	}

	queryData := struct {
		TableName    string
		NeedIdentity bool
		Region       string
		Role         string
		Time         timeRange
		IdentityARN  string
		ErrorCode    string
		EventSource  string
		EventName    string
		Count        string
	}{
		TableName:    tableName,
		NeedIdentity: flags.includeUserIdentity,
		Region:       flags.region,
		Role:         role,
		Time:         timeR,
		IdentityARN:  keyIdentityARN,
		ErrorCode:    keyErrorCode,
		EventSource:  keyEventSource,
		EventName:    keyEventName,
		Count:        keyCount,
	}

	if queryType == queryForUsage {
		queryString := `
SELECT useridentity.sessioncontext.sessionissuer.arn,{{ if .NeedIdentity }}useridentity.arn AS {{.IdentityARN}},{{end}}{{.EventSource}},{{.EventName}},count({{.EventName}}) AS {{.Count}}
FROM {{.TableName}}
WHERE region='{{.Region}}'
    AND year IN ({{ $first := true }}{{ range $v := .Time.Years }}{{if $first }}{{$first = false }}{{else}},{{ end -}} '{{ $v}}'{{ end }})
	AND month IN ({{ $first := true }}{{ range $v := .Time.Months}}{{if $first }}{{$first = false }}{{else}},{{ end -}} '{{printf "%02d" $v}}'{{ end }})
	AND day IN ({{ $first := true }}{{ range $v := .Time.Days}}{{if $first }}{{$first = false }}{{else}},{{ end -}} '{{printf "%02d" $v}}'{{ end }})
	AND eventtime >= '{{index .Time.EventTimeRange 0}}'
	AND eventtime <= '{{index .Time.EventTimeRange 1}}'{{if ne .Role ""}}
	AND useridentity.sessioncontext.sessionissuer.arn LIKE '{{.Role}}'{{ end }}
GROUP BY useridentity.arn,{{.EventSource}},{{.EventName}},useridentity.sessioncontext.sessionissuer.arn
ORDER BY useridentity.arn,{{.Count}} DESC
`
		t := template.Must(template.New("").Parse(queryString))
		err := t.Execute(&tpl, queryData)
		if err != nil {
			logrus.Errorf("error constructing the usage Athena query: %v", err)
			os.Exit(1) // intentional
		}
	} else if queryType == queryForErrors {
		queryString := `
SELECT useridentity.sessioncontext.sessionissuer.arn,{{ if .NeedIdentity }}useridentity.arn AS {{.IdentityARN}},{{end}}{{.EventSource}},{{.EventName}},{{.ErrorCode}},count(useridentity.sessioncontext.sessionissuer.arn) AS {{.Count}}
FROM {{.TableName}}
WHERE region='{{.Region}}'
    AND year IN ({{ $first := true }}{{ range $v := .Time.Years}}{{if $first}}{{$first = false}}{{else}},{{ end -}}'{{ $v}}'{{ end }})
    AND month IN ({{ $first := true }}{{ range $v := .Time.Months}}{{if $first}}{{$first = false}}{{else}},{{ end -}}'{{printf "%02d" $v}}'{{ end }})
    AND day IN ({{ $first := true }}{{ range $v := .Time.Days}}{{if $first}}{{$first = false}}{{else}},{{ end -}}'{{printf "%02d" $v}}'{{ end }})
	AND eventtime >= '{{index .Time.EventTimeRange 0}}'
	AND eventtime <= '{{index .Time.EventTimeRange 1}}'
	AND useridentity.arn != ''{{ if ne .Role ""}}
	AND useridentity.sessioncontext.sessionissuer.arn LIKE '{{.Role}}'{{ end }}
	AND ({{.ErrorCode}} LIKE '%UnauthorizedOperation' OR {{.ErrorCode}} LIKE 'AccessDenied%')
GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,{{.EventSource}},{{.EventName}},{{.ErrorCode}}
ORDER BY useridentity.arn,{{.Count}} DESC
`
		t := template.Must(template.New("").Parse(queryString))
		err := t.Execute(&tpl, queryData)
		if err != nil {
			logrus.Errorf("error constructing the error Athena query: %v", err)
			os.Exit(1) // intentional
		}
	}
	query := tpl.String()
	// Be aware of this for https://github.com/kris-nova/logger/pull/4
	// AND (errorcode LIKE '%!U(MISSING)nauthorizedOperation' OR errorcode LIKE 'AccessDenied%!'(MISSING))
	logrus.Debugf("constructred query: %s", query)
	return query
}

// getAbsoluteTime is helper function to covert relative time to absolute time
func getAbsoluteTime(timeRelative int, now time.Time) string {
	var startTime, endTime time.Time
	if timeRelative != 0 {
		endTime = now
		startTime = endTime.AddDate(0, 0, -timeRelative)
	} else {
		endTime = now
		startTime = now
	}
	y1, m1, d1 := startTime.Date()
	y2, m2, d2 := endTime.Date()
	absTime := fmt.Sprintf("%02d/%02d/%d-%02d/%02d/%d", int(m1), d1, y1, int(m2), d2, y2)
	logrus.Debugf("converted relative time: %d days to absolute time: %s", timeRelative, absTime)
	return absTime
}

// constructPartitionDataFromTime help extract partitions that can be used for the query
func constructPartitionDataFromTime(timeAbsolute string) timeRange {
	var startTime, endTime time.Time
	dates := strings.Split(timeAbsolute, "-")
	startDate, endDate := dates[0], dates[1]
	format := "01/02/2006" // mm/dd/yyyy format
	var err error
	// convert to time
	startTime, err = time.Parse(format, startDate)
	if err != nil {
		logrus.Errorf("could not parse start time from given abolutetime %s", timeAbsolute)
		os.Exit(1)
	}
	endTime, err = time.Parse(format, endDate)
	if err != nil {
		logrus.Errorf("could not parse end time from given abolutetime %s", timeAbsolute)
		os.Exit(1)
	}
	years := make([]int, 0)
	months := make([]int, 0)
	days := make([]int, 0)
	eventTimeRange := make([]string, 0)

	y1, m1, d1 := startTime.Date()
	y2, m2, d2 := endTime.Date()
	yDif := int(y2 - y1)
	mDif := int(m2 - m1)
	dDif := int(d2 - d1)

	// Normalize negative values
	if dDif < 0 {
		// days in month:
		t := time.Date(y1, m1, 32, 0, 0, 0, 0, time.UTC)
		dDif += 32 - t.Day()
		mDif--
		months = append(months, int(m2))
	}
	if mDif < 0 {
		mDif += 12
		yDif--
		years = append(years, y2)
	}
	//get the event time range with RFC3339 layout
	eventStart := time.Date(y1, m1, d1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	eventEnd := time.Date(y2, m2, d2, 23, 59, 59, 999, time.UTC).Format(time.RFC3339)
	eventTimeRange = append(eventTimeRange, []string{eventStart, eventEnd}...)

	// lets determine the partitions for the given dates
	if yDif > 0 {
		for yDif >= 0 {
			years = append(years, y1)
			y1 = y1 + 1
			yDif--
		}
		months = []int{}
		for i := 1; i <= 12; i++ {
			months = append(months, i)
		}
		for i := 1; i <= 31; i++ {
			days = append(days, i)
		}
	} else {
		years = append(years, y1)
		if mDif == 0 {
			months = append(months, int(m1))

			for dDif >= 0 {
				days = append(days, d1)
				d1 = d1 + 1
				if d1 == 32 {
					d1 = 1
				}
				dDif--
			}
		} else if mDif == 1 {
			months = append(months, []int{int(m1), int(m1 + 1)}...)
			if dDif >= 29 || dDif == 0 {
				for i := 1; i <= 31; i++ {
					days = append(days, i)
				}
			} else {
				for dDif > 0 {
					days = append(days, d1)
					if d1 == d2 {
						break
					}
					d1 = d1 + 1
					if d1 == 32 {
						d1 = 1
					}
					dDif--
				}
			}
		} else {
			for mDif >= 0 {
				months = append(months, int(m1))
				m1 = m1 + 1
				if m1 == 13 { //can't be 13
					m1 = 1
				}
				mDif--
			}
			for i := 1; i <= 31; i++ {
				days = append(days, i)
			}
		}
	}
	sort.Ints(months)
	sort.Ints(days)
	sort.Ints(years)
	logrus.Debugf("converted partition data from absolute time: %s is %v", timeAbsolute, timeRange{months, days, years, eventTimeRange})
	return timeRange{months, days, years, eventTimeRange}
}
