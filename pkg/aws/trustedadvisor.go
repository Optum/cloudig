package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/support"
)

// TrustedAdvisorSVC is a wrapper for Support API calls related to TrustedAdvisor
type TrustedAdvisorSVC interface {
	GetFailingTrustedAdvisorCheckResults() (map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult, error)
}

// GetFailingTrustedAdvisorCheckResults returns all failing trusted advisor checks with detailed results
func (client *Client) GetFailingTrustedAdvisorCheckResults() (map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult, error) {
	language := "en"
	result := make(map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult)
	allChecksOutput, err := client.TrustedAdvisor.DescribeTrustedAdvisorChecks(&support.DescribeTrustedAdvisorChecksInput{Language: aws.String(language)})
	if err != nil {
		return nil, err
	}

	for _, check := range allChecksOutput.Checks {
		checkResultOutput, err := client.TrustedAdvisor.DescribeTrustedAdvisorCheckResult(
			&support.DescribeTrustedAdvisorCheckResultInput{
				CheckId:  check.Id,
				Language: aws.String(language)},
		)
		if err != nil {
			return nil, err
		}
		// no constants available
		if aws.StringValue(checkResultOutput.Result.Status) != "not_available" && aws.StringValue(checkResultOutput.Result.Status) != "ok" {
			result[check] = checkResultOutput.Result
		}
	}
	return result, nil
}
