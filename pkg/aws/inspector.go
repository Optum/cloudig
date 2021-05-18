package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/inspector"
)

// InspectorSVC is a wrapper for Inspector API calls
type InspectorSVC interface {
	GenerateReport(assessmentRunArn string, reportFormat string, reportType string) (string, error)
	GetResourceGroupTags(assessmentTargetArn string) (map[string]string, error)
	GetMostRecentAssessmentRunInfo() ([]map[string]string, error)
}

// GenerateReport generates an inspector report for a given assessment run ARN in either PDF or HTML and returns the URL
func (client *Client) GenerateReport(assessmentRunArn string, reportFormat string, reportType string) (string, error) {
	input := &inspector.GetAssessmentReportInput{
		AssessmentRunArn: aws.String(assessmentRunArn),
		ReportFileFormat: aws.String(reportFormat),
		ReportType:       aws.String(reportType),
	}

	report, err := client.Inspector.GetAssessmentReport(input)
	if err != nil {
		return "", err
	}

	return aws.StringValue(report.Url), nil
}

// GetResourceGroupTags returns the resource group tags for a given assessment target ARN
func (client *Client) GetResourceGroupTags(assessmentTargetArn string) (map[string]string, error) {
	targetInfo, err := client.Inspector.DescribeAssessmentTargets(
		&inspector.DescribeAssessmentTargetsInput{
			AssessmentTargetArns: []*string{aws.String(assessmentTargetArn)},
		},
	)
	if err != nil {
		return nil, err
	}

	resourceGroupInfo, err := client.Inspector.DescribeResourceGroups(
		&inspector.DescribeResourceGroupsInput{
			ResourceGroupArns: []*string{targetInfo.AssessmentTargets[0].ResourceGroupArn},
		},
	)
	if err != nil {
		return nil, err
	}

	tags := make(map[string]string, len(resourceGroupInfo.ResourceGroups[0].Tags))
	for _, tag := range resourceGroupInfo.ResourceGroups[0].Tags {
		tags[aws.StringValue(tag.Key)] = aws.StringValue(tag.Value)
	}

	return tags, nil
}

// GetMostRecentAssessmentRunInfo returns the most recent assessment run and target group ARNs for each template
func (client *Client) GetMostRecentAssessmentRunInfo() ([]map[string]string, error) {
	templates, err := client.Inspector.ListAssessmentTemplates(&inspector.ListAssessmentTemplatesInput{})
	if err != nil {
		return nil, err
	}

	templateInfo, err := client.Inspector.DescribeAssessmentTemplates(
		&inspector.DescribeAssessmentTemplatesInput{
			AssessmentTemplateArns: templates.AssessmentTemplateArns,
		},
	)
	if err != nil {
		return nil, err
	}

	assessmentRunInfo := make([]map[string]string, 0)
	for _, template := range templateInfo.AssessmentTemplates {
		// Only return information on assessment templates that have been run
		if *template.LastAssessmentRunArn != "" {
			assessmentRunInfo = append(assessmentRunInfo, map[string]string{
				"templateName": aws.StringValue(template.Name),
				"targetArn":    aws.StringValue(template.AssessmentTargetArn),
				"arn":          aws.StringValue(template.LastAssessmentRunArn),
			})
		}
	}

	return assessmentRunInfo, nil
}
