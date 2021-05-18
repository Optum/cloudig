package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/configservice"
)

// ConfigServiceSVC is a wrapper for ConfigService API calls
type ConfigServiceSVC interface {
	GetNonComplaintConfigRules() (map[string][]*configservice.EvaluationResult, error)
}

// GetNonComplaintConfigRules returns all the non complaint rules with compliance results
func (client *Client) GetNonComplaintConfigRules() (map[string][]*configservice.EvaluationResult, error) {
	var rulesNextToken *string
	var rulesComplianceNextToken *string
	results := make(map[string][]*configservice.EvaluationResult)
	for {
		configRuleOutput, err := client.AWSConfig.DescribeComplianceByConfigRule(&configservice.DescribeComplianceByConfigRuleInput{
			NextToken: rulesNextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, v := range configRuleOutput.ComplianceByConfigRules {
			if aws.StringValue(v.Compliance.ComplianceType) != configservice.ComplianceTypeInsufficientData && aws.StringValue(v.Compliance.ComplianceType) != configservice.ComplianceTypeCompliant {
				evaluationResults := make([]*configservice.EvaluationResult, 0)
				for {
					configRuleComplianceOutput, err := client.AWSConfig.GetComplianceDetailsByConfigRule(&configservice.GetComplianceDetailsByConfigRuleInput{
						ConfigRuleName: v.ConfigRuleName,
						Limit:          aws.Int64(100),
						NextToken:      rulesComplianceNextToken,
					})

					if err != nil {
						return nil, err
					}
					evaluationResults = append(evaluationResults, configRuleComplianceOutput.EvaluationResults...)

					rulesComplianceNextToken = configRuleComplianceOutput.NextToken
					if rulesComplianceNextToken == nil {
						break
					}

				}
				results[aws.StringValue(v.ConfigRuleName)] = evaluationResults
			}

		}
		rulesNextToken = configRuleOutput.NextToken
		if rulesNextToken == nil {
			break
		}

	}

	return results, nil
}
