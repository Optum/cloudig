package cloudig

import (
	"strings"
	"time"

	awslocal "github.com/Optum/cloudig/pkg/aws"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/support"
	"github.com/kris-nova/logger"
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
	logger.Info("working on TrustedAdvisorReport for account: %s", accountID)
	logger.Info("finding failing Trusted Advisor checks for account: %s", accountID)
	results, err := client.GetFailingTrustedAdvisorCheckResults()
	if err != nil {
		return err
	}

	report.Findings = append(report.Findings, processTrustedAdvisorResults(results, accountID, comments)...)
	logger.Success("getting AWS TrustedAdvisorReport for account %s took %s", finding.AccountID, time.Since(start))
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
				if !awslocal.SdkStringContains(resource.Metadata, aws.String("Green")) && aws.BoolValue(resource.IsSuppressed) == false {
					var flaggedResource string
					// if not region, important flagged resource will be in field 1
					if len(resource.Metadata) > 1 {
						flaggedResource = aws.StringValue(resource.Metadata[1])
					} else if len(resource.Metadata) == 1 {
						// only pick metadata 0 if no other option
						flaggedResource = aws.StringValue(resource.Metadata[0])
					}

					// clarify which region flaggedResource is part of
					regionIndex := -1
					for i, metadata := range check.Metadata {
						// Convers Region and Region/AZ and other variations
						if strings.Contains(aws.StringValue(metadata), "Region") {
							regionIndex = i
							break
						}
					}
					if regionIndex > -1 && len(resource.Metadata) >= (regionIndex+1) && aws.StringValue(resource.Metadata[regionIndex]) != "" {
						// important resource is after region in metadata
						flaggedResource = strings.Join([]string{aws.StringValue(resource.Metadata[regionIndex]), aws.StringValue(resource.Metadata[regionIndex+1])}, "/")
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
