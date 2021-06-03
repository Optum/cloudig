package cloudig

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/sirupsen/logrus"

	awslocal "github.com/Optum/cloudig/pkg/aws"
)

// ConfigReport is a struct that contains an array of aws config compliance findings
type ConfigReport struct {
	Findings []configFinding `json:"findings"`
	jsonOutputHelper
}

type configFinding struct {
	AccountID string `json:"accountId"`
	RuleName  string `json:"ruleName"`
	//Description      string
	Status           string              `json:"status"`
	FlaggedResources map[string][]string `json:"flaggedResources"`
	Comments         string              `json:"comments"`
}

type configComplianceResult struct {
	name         string
	status       string
	resultOutput []*configservice.EvaluationResult
}

// GetReport retrives the aws config compliance report for a given account,
func (report *ConfigReport) GetReport(client awslocal.APIs, comments []Comments) error {
	start := time.Now()
	finding := configFinding{}

	// Get accountID from session
	accountID, err := client.GetAccountID()
	if err != nil {
		return err
	}
	logrus.Infof("working on AWSConfigCompliance report for account: %s", accountID)
	finding.AccountID = accountID

	logrus.Infof("finding failing compliance config rules for account: %s", accountID)
	results, err := client.GetNonComplaintConfigRules()
	if err != nil {
		return err
	}

	// Parse results into findings
	report.Findings = append(report.Findings, processConfigResults(results, finding, comments)...)

	logrus.Infof("getting AWSConfigCompliance for account %s took %s", finding.AccountID, time.Since(start))
	return nil
}

func processConfigResults(results map[string][]*configservice.EvaluationResult, finding configFinding, comments []Comments) []configFinding {
	var findings []configFinding
	for name, result := range results {
		finding.RuleName = name
		finding.Status = configservice.ComplianceTypeNonCompliant // keeping this for backword compatibility
		finding.Comments = getComments(comments, finding.AccountID, findingTypeAWSConfig, finding.RuleName)
		flaggedResources := []string{}
		for _, evaluationResult := range result {
			if aws.StringValue(evaluationResult.ComplianceType) != configservice.ComplianceTypeCompliant {
				flaggedResources = append(flaggedResources, aws.StringValue(evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId))
			}
		}
		finding.FlaggedResources = map[string][]string{aws.StringValue(result[0].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType): flaggedResources}
		findings = append(findings, finding)
	}

	return findings
}
