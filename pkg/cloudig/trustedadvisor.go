package cloudig

import (
	"strings"
	"time"

	awslocal "github.com/Optum/cloudig/pkg/aws"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/support"
	"github.com/sirupsen/logrus"
)

// TrustedAdvisorReport is struct that contains an array of Trusted Advisor findings
type TrustedAdvisorReport struct {
	Findings []trustedAdvisorFinding `json:"findings"`
	jsonOutputHelper
}

type trustedAdvisorFinding struct {
	AccountID        string                                 `json:"accountId"`
	Category         string                                 `json:"category"`
	Name             string                                 `json:"name"`
	Description      string                                 `json:"description"`
	Status           string                                 `json:"status"`
	ResourcesSummary support.TrustedAdvisorResourcesSummary `json:"resourcesSummary"` // map[string]int64
	FlaggedResources []string                               `json:"flaggedResources"`
	Comments         string                                 `json:"comments"`
}

// GetReport retrives the trusted advisor report for a given account,
func (report *TrustedAdvisorReport) GetReport(client awslocal.APIs, comments []Comments) error {
	start := time.Now()
	finding := trustedAdvisorFinding{}

	// Get accountID from roleARN
	accountID, err := client.GetAccountID()
	if err != nil {
		return err
	}
	logrus.Infof("working on TrustedAdvisorReport for account: %s", accountID)
	logrus.Infof("finding failing Trusted Advisor checks for account: %s", accountID)
	results, err := client.GetFailingTrustedAdvisorCheckResults()
	if err != nil {
		return err
	}

	report.Findings = processTrustedAdvisorResults(results, accountID, comments)
	logrus.Infof("getting AWS TrustedAdvisorReport for account %s took %s", finding.AccountID, time.Since(start))
	return nil
}

func processTrustedAdvisorResults(results map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult, accountID string, comments []Comments) []trustedAdvisorFinding {
	findings := make([]trustedAdvisorFinding, 0)
	for check, result := range results {
		finding := trustedAdvisorFinding{
			AccountID:        accountID,
			Category:         strings.ToUpper(aws.StringValue(check.Category)),
			Name:             aws.StringValue(check.Name),
			Description:      strings.TrimSpace(strings.Split(aws.StringValue(check.Description), "<br")[0]),
			Status:           aws.StringValue(result.Status),
			ResourcesSummary: *result.ResourcesSummary,
			FlaggedResources: []string{},
		}
		finding.Comments = getComments(comments, finding.AccountID, findingTypeTrustedAdvisor, finding.Category+"-"+strings.Replace(finding.Name, " ", "_", -1))
		for _, resource := range result.FlaggedResources {
			if resource.Metadata != nil {
				if aws.StringValue(resource.Metadata[0]) != "Green" {
					flaggedResource := aws.StringValue(resource.Metadata[1])
					if aws.StringValue(resource.Metadata[2]) != "" && aws.StringValue(check.Metadata[1]) == "Region" {
						flaggedResourceMeta := aws.StringValue(resource.Metadata[2])
						flaggedResource = strings.Join([]string{flaggedResource, flaggedResourceMeta}, "/")
					}
					finding.FlaggedResources = append(finding.FlaggedResources, flaggedResource)
				}
			} else {
				finding.FlaggedResources = append(finding.FlaggedResources, "NA")
			}
		}
		findings = append(findings, finding)
	}
	return findings
}
