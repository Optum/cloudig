package cloudig

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	awslocal "github.com/Optum/cloudig/pkg/aws"
)

// InspectorReports is a struct that contains an array of inspectorReport
type InspectorReports struct {
	Reports []inspectorReport `json:"reports"`
	Helper  reportDownloader  `json:"-"`
	jsonOutputHelper
}

type inspectorReport struct {
	AccountID    string                   `json:"accountId"`
	TemplateName string                   `json:"templateName"`
	Findings     []inspectorReportFinding `json:"findings"`
	AMI          map[string]int           `json:"amis"`
}

type inspectorReportFinding struct {
	RulePackageName string `json:"rulePackage"`
	High            string `json:"high"`
	Medium          string `json:"medium"`
	Low             string `json:"low"`
	Informational   string `json:"informational"`
	Comments        string `json:"comments"`
}

// InspectorHelper is a struct that implements the reportDownloader interface inorder to fake downloading a report for testing scenarios
type InspectorHelper struct{}

type reportDownloader interface {
	downloadReport(reportURL string, report inspectorReport) (string, error)
}

// GetReport builds the Inspector report for a given assessment run
func (reports *InspectorReports) GetReport(client awslocal.APIs, comments []Comments) error {
	start := time.Now()
	report := inspectorReport{}

	// Get accountID from session
	accountID, err := client.GetAccountID()
	if err != nil {
		return err
	}
	logrus.Infof("working on Inspector report for account: %s", accountID)
	report.AccountID = accountID

	logrus.Infof("finding most recent assessment run for template(s) in account: %s", accountID)
	// Get most recent Assessment Run ARNs for each template
	assessmentRunInfo, err := client.GetMostRecentAssessmentRunInfo()
	if err != nil {
		return err
	}

	// Generate report from ARN and download file
	for _, run := range assessmentRunInfo {
		report.TemplateName = run["templateName"]
		reportURL, err := client.GenerateReport(run["arn"], "HTML", "FULL")
		if err != nil {
			return err
		}
		logrus.Infof("generating a report for %s in account: %s", run["templateName"], accountID)

		reportFile, err := reports.Helper.downloadReport(reportURL, report)
		if err != nil {
			return err
		}

		logrus.Infof("parsing report for findings in account: %s", accountID)
		// Parse report page HTML and build table of findings
		reportFindings, err := getReportFindings(reportFile, comments, report)
		if err != nil {
			return err
		}
		report.Findings = reportFindings

		logrus.Infof("finding AMI properties associated with the scan in account: %s", accountID)

		// Get list of AMIS that have a given list of tags and their age in days
		amiAgeMap, err := getAssessmentRunAgentAMIAndAge(client, run["targetArn"])
		if err != nil {
			return err
		}
		report.AMI = amiAgeMap

		// Add to final report
		reports.Reports = append(reports.Reports, report)

	}

	logrus.Infof("getting Inspector Report for account %s took %s", report.AccountID, time.Since(start))
	return nil
}

func getReportFindings(reportFile string, comments []Comments, report inspectorReport) ([]inspectorReportFinding, error) {
	var reportFindings []inspectorReportFinding
	// Parse report page HTML, build list of findings, then delete report
	table, err := parseReportTable(reportFile)
	if err != nil {
		return nil, err
	}

	err = deleteFile(reportFile)
	if err != nil {
		return nil, err
	}

	for _, row := range table {
		inspectorReportFinding := inspectorReportFinding{}
		for index, col := range row {
			switch index {
			case 0:
				inspectorReportFinding.RulePackageName = col
			case 1:
				inspectorReportFinding.High = col
			case 2:
				inspectorReportFinding.Medium = col
			case 3:
				inspectorReportFinding.Low = col
			case 4:
				inspectorReportFinding.Informational = col
			default:
				logrus.Warnf("error parsing finding table from the report")
			}
		}

		reportFindings = append(reportFindings, inspectorReportFinding)
	}

	// Get comments for findings
	for i, finding := range reportFindings {
		// Format rule package name into comment format
		// ex. CIS Operating System Security Configuration 1.0 => CIS_Operating_System_Security_Configuration-1.0
		commentFinding := strings.Replace(finding.RulePackageName, " ", "_", -1)
		reportFindings[i].Comments = ""
		if !isZeroFindings(finding) {
			reportFindings[i].Comments = getComments(comments, report.AccountID, findingTypeInspector, commentFinding)
		}
	}

	return reportFindings, nil
}

func isZeroFindings(finding inspectorReportFinding) bool {
	if finding.High == "0" && finding.Medium == "0" && finding.Low == "0" && finding.Informational == "0" {
		return true
	}
	return false
}

// Parse report, build table, and delete report
func parseReportTable(filepath string) ([][]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	doc, err := goquery.NewDocumentFromReader(file)
	if err != nil {
		return nil, err
	}

	var table [][]string
	doc.Find("tbody").Each(func(index int, tablehtml *goquery.Selection) {
		// Only parse second table
		if index == 1 {
			tablehtml.Find("tr").Each(func(indextr int, rowhtml *goquery.Selection) {
				// Don't parse header row
				var row []string
				if indextr > 0 {
					rowhtml.Find("td").Each(func(indextd int, tablecell *goquery.Selection) {
						row = append(row, strings.TrimSpace(tablecell.Text()))
					})
					table = append(table, row)
				}
			})
		}
	})

	return table, nil
}

func getAgeInDays(creationDate string) int {
	today := time.Now()
	date, _ := time.Parse(time.RFC3339, creationDate)
	timeInDays := int(today.Sub(date).Hours()) / 24

	return timeInDays
}

// Get unique list of Image Ids for agents associated with an assessment target
func getAssessmentRunAgentAMIAndAge(client awslocal.APIs, targetArn string) (map[string]int, error) {
	tags, err := client.GetResourceGroupTags(targetArn)
	if err != nil {
		return nil, err
	}

	instancesList, err := client.GetInstancesMatchingAnyTags(tags)
	if err != nil {
		return nil, err
	}

	amiList := unique(getAmiList(instancesList))

	// Get age of AMIs in days
	imageInformation, err := client.GetImageInformation(amiList)
	if err != nil {
		return nil, err
	}
	amiAgeMap := getAmiAgeMap(imageInformation)

	return amiAgeMap, nil
}

func getAmiList(instancesList *ec2.DescribeInstancesOutput) []string {
	var amiList []string

	for _, res := range instancesList.Reservations {
		for _, inst := range res.Instances {
			amiList = append(amiList, aws.StringValue(inst.ImageId))
		}
	}
	return amiList
}

func getAmiAgeMap(imageInformation *ec2.DescribeImagesOutput) map[string]int {
	amiAgeMap := make(map[string]int)
	for _, image := range imageInformation.Images {
		amiAgeMap[aws.StringValue(image.Name)] = getAgeInDays(aws.StringValue(image.CreationDate))
	}
	return amiAgeMap
}

func unique(amiList []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range amiList {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func downloadFile(filepath string, url string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func (helper *InspectorHelper) downloadReport(reportURL string, report inspectorReport) (string, error) {
	reportFile := "/tmp/inspector_report_" + report.AccountID + ".html"
	// Download report to tmp folder
	err := downloadFile(reportFile, reportURL)
	if err != nil {
		return "", err
	}
	return reportFile, nil
}

func deleteFile(filePath string) error {
	err := os.Remove(filePath)
	if err != nil {
		return err
	}
	return nil
}
