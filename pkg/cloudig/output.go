package cloudig

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kris-nova/logger"
	"github.com/olekukonko/tablewriter"
)

const (
	tableTypeNormal string = "table"
	tableTypeMD     string = "mdtable"
)

type jsonOutputHelper struct {
	ReportTime string `json:"reportTime"`
}

func (helper *jsonOutputHelper) toJSON(report *Report) string {
	helper.ReportTime = getCurrentTimestamp()
	content, err := json.MarshalIndent(report, "", "  ")

	if err != nil {
		logger.Critical("unable to marshal the output into JSON: %v", err)
	}
	return string(content)
}

func (report *TrustedAdvisorReport) toTable(tableType string) string {
	report.ReportTime = getCurrentTimestamp()
	table, tableString := getTableWriterWithHeaders(tableType, []string{"Account ID", "Name", "Flagged Resources", "Comments"})
	// build table rows
	for _, finding := range report.Findings {
		nameCol := finding.Category + "\n" + finding.Name
		flaggedResourcesCol := "Flagged Count: " + strconv.Itoa(len(finding.FlaggedResources)) + "\n" + strings.Join(finding.FlaggedResources, "\n")
		table.Append([]string{finding.AccountID, nameCol, flaggedResourcesCol, finding.Comments})
	}

	logger.Always("report Time: %s", report.ReportTime)
	table.Render()

	return tableString.String()
}

func (report *ConfigReport) toTable(tableType string) string {
	report.ReportTime = getCurrentTimestamp()

	table, tableString := getTableWriterWithHeaders(tableType, []string{"Account ID", "Name", "Flagged Resources", "Comments"})
	// build table rows
	for _, finding := range report.Findings {
		var flaggedResourcesCol string
		for resourceType, flaggedResources := range finding.FlaggedResources {
			flaggedResourcesCol = "Resource Type: " + resourceType + "\n" + strings.Join(flaggedResources, "\n")
		}
		table.Append([]string{finding.AccountID, finding.RuleName, flaggedResourcesCol, finding.Comments})
	}

	logger.Always("report Time: %s", report.ReportTime)
	table.Render()

	return tableString.String()
}

func (reports *InspectorReports) toTable(tableType string) string {
	reports.ReportTime = getCurrentTimestamp()
	findingsTable, findingsTableString := getTableWriterWithHeaders(tableType, []string{"Account ID", "Template Name", "Rule Packages", "High", "Medium", "Low", "Informational", "Comments"})

	amiTable, amiTableString := getTableWriterWithHeaders(tableType, []string{"Account ID", "AMI", "Age"})
	amiTable.SetAutoMergeCells(true)

	// build tables
	for _, report := range reports.Reports {
		for _, finding := range report.Findings {
			findingsTable.Append([]string{report.AccountID, report.TemplateName, finding.RulePackageName, finding.High, finding.Medium, finding.Low, finding.Informational, finding.Comments})
		}
	}

	for _, report := range reports.Reports {
		for ami, age := range report.AMI {
			amiTable.Append([]string{report.AccountID, ami, strconv.Itoa(age) + " days"})
		}
	}

	logger.Always("report Time: %s", reports.ReportTime)
	findingsTable.Render()
	amiTable.Render()

	return findingsTableString.String() + amiTableString.String()
}

func (report *HealthReport) toTable(tableType string) string {
	report.ReportTime = getCurrentTimestamp()

	table, tableString := getTableWriterWithHeaders(tableType, []string{"Account ID", "Event Type Code", "Region", "Status Code", "Event Description", "Affected Resources", "Comments"})
	// build table rows
	for _, finding := range report.Findings {
		table.Append([]string{finding.AccountID, finding.EventTypeCode, finding.Region, finding.StatusCode, finding.EventDescription, strings.Join(finding.AffectedEntities, ", "), finding.Comments})
	}

	logger.Always("report Time: %s", report.ReportTime)
	table.Render()

	return tableString.String()
}

func (report *ImageScanReports) toTable(tableType string) string {
	report.ReportTime = getCurrentTimestamp()

	table, tableString := getTableWriterWithHeaders(tableType, []string{"Account ID", "Region", "Repository Name", "Tag", "Vulnerabilities(count)", "Comments"})
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	// build table rows
	previousAccountID := ""
	previousRepo := ""
	previousRegion := ""
	for _, finding := range report.Findings {
		var severityCount string
		for severity, count := range finding.ImageFindingsCount {
			severityCount = severityCount + fmt.Sprintf("%-15v %d\n", severity+":", count)
		}
		severityCount = strings.Trim(severityCount, "\n")
		if previousAccountID != finding.AccountID && previousRepo != finding.RepositoryName && previousRegion != finding.Region {
			table.Append([]string{finding.AccountID, finding.Region, finding.RepositoryName, finding.ImageTag, severityCount, finding.Comments})
		} else if previousAccountID == finding.AccountID && previousRegion != finding.Region && previousRepo != finding.RepositoryName {
			table.Append([]string{"", finding.Region, finding.RepositoryName, finding.ImageTag, severityCount, finding.Comments})
		} else if previousAccountID == finding.AccountID && previousRegion == finding.Region && previousRepo != finding.RepositoryName {
			table.Append([]string{"", "", finding.RepositoryName, finding.ImageTag, severityCount, finding.Comments})
		} else {
			table.Append([]string{"", "", "", finding.ImageTag, severityCount, finding.Comments})
		}
		previousAccountID = finding.AccountID
		previousRepo = finding.RepositoryName
		previousRegion = finding.Region
	}

	logger.Always("report Time: %s", report.ReportTime)
	table.Render()

	return tableString.String()
}

func (report *ReflectReport) toTable(tableType string) string {
	report.ReportTime = getCurrentTimestamp()

	table, tableString := getTableWriterWithHeaders(tableType, []string{"Account ID", "IAM Identity", "Access Details", "Actual Permissions", "Comments"})
	// build table rows
	for _, finding := range report.Findings {
		details := make([]string, 0)
		for _, ad := range finding.AccessDetails {
			details = append(details, ad.Event+":"+strconv.Itoa(ad.Count))
		}
		accDetCol := strings.Join(details, "\n")
		perSetCol := strings.Join(finding.PermissionSet, "\n")
		table.Append([]string{finding.AccountID, finding.Identity, accDetCol, perSetCol, finding.Comments})
	}

	logger.Always("report Time: %s", report.ReportTime)
	table.Render()

	return tableString.String()
}

func getCurrentTimestamp() string {
	return time.Now().Format(time.RFC822)
}

func getTableWriterWithHeaders(tableType string, headers []string) (*tablewriter.Table, *strings.Builder) {
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader(headers)
	if tableType == tableTypeNormal {
		table.SetRowLine(true)
		table.SetRowSeparator("-")
	} else if tableType == tableTypeMD {
		table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
		table.SetCenterSeparator("|")
	}
	return table, tableString
}
