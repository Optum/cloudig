package cloudig

import (
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"

	awslocal "github.com/Optum/cloudig/pkg/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/sirupsen/logrus"
)

// Comments is a Collection of user comments mapped to yaml structure
type Comments struct {
	AccountID               string              `yaml:"accountid"`
	TAFindings              []map[string]string `yaml:"ta-findings"`
	ConfigFindings          []map[string]string `yaml:"config-findings"`
	InspectorReportFindings []map[string]string `yaml:"inspector-findings"`
	HealthReportFindings    []map[string]string `yaml:"health-findings"`
	ImageScanFindings       []map[string]string `yaml:"ecr-findings"`
	ReflectIAMFindings      []map[string]string `yaml:"reflect-iam-findings"`
}

const (
	findingTypeTrustedAdvisor string = "ta"
	findingTypeAWSConfig      string = "config"
	findingTypeInspector      string = "inspector"
	findingTypeAWSHealth      string = "health"
	findingTypeReflectIAM     string = "reflectIAM"
	findingTypeECRScan        string = "ecrscan"
)

// Report is an interface that all types of reports will implement
type Report interface {
	GetReport(client awslocal.APIs, comments []Comments) error
	toJSON(report *Report) string
	toTable(tableType string) string
}

// ProcessReport collects the different reports for each account concurrently
func ProcessReport(sess *session.Session, report Report, outputType string, commentsFile string, roleARNs string) error {
	var wg sync.WaitGroup

	// Parse comments file into map and pass to report
	comments := parseCommentsFile(commentsFile)
	accounts := parseRoleARNs(roleARNs)
	logrus.Debugf("accounts derived from role ARN is: %v", accounts)
	parentClient := awslocal.NewClient(sess)

	// Add all go routines to be executed to wait group for effective synchronization
	wg.Add(len(accounts))
	es := make([]string, 0)
	for i := 0; i < len(accounts); i++ {
		go func(i int) {
			defer wg.Done()

			// if not the parent account, create a new Client that assumes the role tied to the other account
			client := parentClient
			if accounts[i] != "parent" {
				client = awslocal.NewClientAsAssumeRole(sess, accounts[i])
			}

			err := report.GetReport(client, comments)
			if err != nil {
				logrus.Warnf("error getting the report for the account '%s': %v", accounts[i], err)
				es = append(es, err.Error())
			}

		}(i)
	}
	// Wait till all called in go routines are completed successfully
	wg.Wait()

	// output only if there is no error on at least one of the account
	if len(es) != len(accounts) {
		outputReport(report, outputType)
	}

	if len(es) != 0 {
		return fmt.Errorf(strings.Join(es, "\n"))
	}
	return nil
}

// OutputReport outputs a report as JSON, an ASCII table, or a markdown table
func outputReport(reportType Report, outputType string) {
	switch outputType {
	case tableTypeNormal:
		fmt.Println(reportType.toTable(tableTypeNormal))
	case tableTypeMD:
		fmt.Println(reportType.toTable(tableTypeMD))
	default:
		fmt.Println(reportType.toJSON(&reportType))
	}
}

// Function that parses comments file into map
func parseCommentsFile(commentsFile string) []Comments {
	var comments []Comments

	content, err := ioutil.ReadFile(commentsFile)
	if err != nil {
		logrus.Warnf("error reading file %s: %v", commentsFile, err)
	} else {
		logrus.Infof("reading comments from file %s", commentsFile)
	}

	err = yaml.Unmarshal(content, &comments)
	if err != nil {
		logrus.Warnf("unable to parse comments from file %s: %v", commentsFile, err)
	}

	return comments
}

func getComments(comments []Comments, findingAcct string, findingType string, findingName string) string {
	for _, ex := range comments {
		if ex.AccountID == findingAcct {
			switch findingType {
			case findingTypeTrustedAdvisor:
				return ContainsKey(ex.TAFindings, findingName)
			case findingTypeAWSConfig:
				return ContainsKey(ex.ConfigFindings, findingName)
			case findingTypeInspector:
				return ContainsKey(ex.InspectorReportFindings, findingName)
			case findingTypeAWSHealth:
				return ContainsKey(ex.HealthReportFindings, findingName)
			case findingTypeReflectIAM:
				return ContainsKey(ex.ReflectIAMFindings, findingName)
			case findingTypeECRScan:
				var allTag string
				tag := strings.Split(findingName, ":")
				if len(tag) >= 2 {
					allTag = "ALL:" + tag[1]
				}
				value := ContainsKey(ex.ImageScanFindings, findingName)
				if value == "NEW_FINDING" {
					return ContainsKey(ex.ImageScanFindings, allTag)
				}
				return value
			default:
				return "NEW_FINDING"
			}
		}
	}
	return "NEW_FINDING"
}

// Function that parses string of role ARNs into array
func parseRoleARNs(roleARNs string) []string {
	accounts := make([]string, 1)
	if roleARNs != "" {
		accounts = strings.Split(roleARNs, ",")
	} else {
		accounts[0] = "parent"
	}

	return accounts
}
