package cloudig

import (
	"errors"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/support"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestTrustedAdvisorGetReport(t *testing.T) {
	testCases := []struct {
		name                                             string
		accountID                                        string
		mockGetFailingTrustedAdvisorCheckResultsResponse map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult
		mockGetAccountIDError                            error
		mockGetFailingTrustedAdvisorCheckResultsError    error
		expectedFindings                                 []trustedAdvisorFinding
		expectedError                                    error
	}{
		{
			name:      "Return expected report",
			accountID: "111111111111",
			mockGetFailingTrustedAdvisorCheckResultsResponse: map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult{
				{
					Category: aws.String("cost_optimizing"),
					Description: aws.String(`Checks the Amazon Elastic Compute Cloud (Amazon EC2) instances that were running at any time during the last 14 days and alerts you if the daily CPU utilization was 10% or less and network I/O was 5 MB or less on 4 or more days. Running instances generate hourly usage charges. Although some scenarios can result in low utilization by design, you can often lower your costs by managing the number and size of your instances.
					<br><br>
					Estimated monthly savings are calculated by using the current usage rate for On-Demand Instances and the estimated number of days the instance might be underutilized. Actual savings will vary if you are using Reserved Instances or Spot Instances, or if the instance is not running for a full day. To get daily utilization data, download the report for this check.
					<br>
					<br>
					<b>Alert Criteria</b><br>
					Yellow: An instance had 10% or less daily average CPU utilization and 5 MB or less network I/O on at least 4 of the previous 14 days.<br>
					<br>
					<b>Recommended Action</b><br>
					Consider stopping or terminating instances that have low utilization, or scale the number of instances by using Auto Scaling. For more information, see <a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Stop_Start.html" target="_blank">Stop and Start Your Instance</a>, <a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html" target="_blank">Terminate Your Instance</a>, and <a href="http://docs.aws.amazon.com/AutoScaling/latest/DeveloperGuide/WhatIsAutoScaling.html" target="_blank">What is Auto Scaling?</a><br>
					<br>
					<b>Additional Resources</b><br>
					<a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-monitoring.html" target="_blank">Monitoring Amazon EC2</a><br>
					<a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AESDG-chapter-instancedata.html" target="_blank">Instance Metadata and User Data</a><br>
					<a href="http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/Welcome.html" target="_blank">Amazon CloudWatch Developer Guide</a><br>
					<a href="http://docs.aws.amazon.com/AutoScaling/latest/DeveloperGuide/WhatIsAutoScaling.html" target="_blank">Auto Scaling Developer Guide</a>`),
					Metadata: aws.StringSlice([]string{"Status", "Region", "instance-id", "Name"}),
					Name:     aws.String("Low Utilization Amazon EC2 Instances"),
				}: {
					Status: aws.String("warning"),
					FlaggedResources: []*support.TrustedAdvisorResourceDetail{
						{
							IsSuppressed: aws.Bool(false),
							Metadata: aws.StringSlice([]string{
								"Yellow",
								"us-east-1",
								"i-0123456789abcdefg",
								"k8s.example.com",
								"m5.2xlarge",
								"$276.48",
								"1.8%  3.34MB",
								"1.7%  3.29MB",
								"1.6%  3.29MB",
								"1.6%  3.32MB",
								"1.6%  3.28MB",
								"1.7%  3.41MB",
								"1.6%  3.43MB",
								"1.6%  3.47MB",
								"1.9%  3.34MB",
								"1.6%  3.29MB",
								"1.6%  3.40MB",
								"1.7%  3.48MB",
								"1.7%  3.51MB",
								"1.7%  3.43MB",
								"1.7%",
								"3.37MB",
								"14 days"},
							),
							Region:     aws.String("us-east-1"),
							ResourceId: aws.String("QtCJL9NshMFH8AHUBLdX_fvrnAOPSTpR-hzxk0YU4oI"),
							Status:     aws.String("warning"),
						},
						{
							IsSuppressed: aws.Bool(false),
							Metadata: aws.StringSlice([]string{
								"Yellow",
								"us-east-1",
								"i-abcdefg0123456789",
								"k8s.example.com",
								"m5.2xlarge",
								"$276.48",
								"1.0%  2.61MB",
								"1.1%  2.57MB",
								"1.0%  2.56MB",
								"1.0%  2.60MB",
								"1.0%  2.55MB",
								"1.0%  2.69MB",
								"1.0%  2.70MB",
								"1.0%  2.73MB",
								"1.1%  2.63MB",
								"1.0%  2.55MB",
								"1.0%  2.66MB",
								"1.0%  2.75MB",
								"1.0%  2.78MB",
								"1.0%  2.70MB",
								"1.0%",
								"2.65MB",
								"14 days"},
							),
							Region:     aws.String("us-east-1"),
							ResourceId: aws.String("M1nMGLq-DqEbS0jbaObJ1IXucGlQ_bcOOBBLQSVcCjU"),
							Status:     aws.String("warning"),
						},
						// This is just to test filtering out resources that have "Green" in their metadata
						{
							Metadata: aws.StringSlice([]string{
								"Green",
							},
							),
						},
					},
					ResourcesSummary: &support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(10),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(12),
						ResourcesSuppressed: aws.Int64(0),
					},
				},
				{
					Category: aws.String("security"),
					Description: aws.String(`Checks for your use of AWS Identity and Access Management (IAM). You can use IAM to create users, groups, and roles in AWS, and you can use permissions to control access to AWS resources.
					<br>
					<br>
					<b>Alert Criteria</b><br>
					Yellow: No IAM users have been created for this account.
					<br>
					<br>
					<b>Recommended Action</b><br>
					Create one or more IAM users and groups in your account. You can then create additional users whose permissions are limited to perform specific tasks in your AWS environment. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/IAMGettingStarted.html" target="_blank">Getting Started</a>.
					<br><br>
					<b>Additional Resources</b><br>
					<a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/IAM_Introduction.html" target="_blank">What Is IAM?</a>`),
					Name: aws.String("IAM Use"),
				}: {
					Status: aws.String("warning"),
					FlaggedResources: []*support.TrustedAdvisorResourceDetail{{
						IsSuppressed: aws.Bool(false),
						ResourceId:   aws.String("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"),
						Status:       aws.String("warning"),
					},
					},
					ResourcesSummary: &support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(1),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(1),
						ResourcesSuppressed: aws.Int64(0),
					},
				},
			},
			expectedFindings: []trustedAdvisorFinding{
				{
					AccountID:   "111111111111",
					Category:    "COST_OPTIMIZING",
					Name:        "Low Utilization Amazon EC2 Instances",
					Description: `Checks the Amazon Elastic Compute Cloud (Amazon EC2) instances that were running at any time during the last 14 days and alerts you if the daily CPU utilization was 10% or less and network I/O was 5 MB or less on 4 or more days. Running instances generate hourly usage charges. Although some scenarios can result in low utilization by design, you can often lower your costs by managing the number and size of your instances.`,
					Status:      "warning",
					ResourcesSummary: support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(10),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(12),
						ResourcesSuppressed: aws.Int64(0),
					},
					FlaggedResources: []string{"us-east-1/i-0123456789abcdefg", "us-east-1/i-abcdefg0123456789"},
					Comments:         "NEW_FINDING",
				}, {
					AccountID:   "111111111111",
					Category:    "SECURITY",
					Name:        "IAM Use",
					Description: "Checks for your use of AWS Identity and Access Management (IAM). You can use IAM to create users, groups, and roles in AWS, and you can use permissions to control access to AWS resources.",
					Status:      "warning",
					ResourcesSummary: support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(1),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(1),
						ResourcesSuppressed: aws.Int64(0),
					},
					FlaggedResources: []string{"NA"},
					Comments:         "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM",
				},
			},
		},
		{
			name:      "Return error when getting Account ID",
			accountID: "",
			mockGetFailingTrustedAdvisorCheckResultsError: errors.New("Some API error"),
			expectedError: errors.New("Some API error"),
		},
		{
			name:      "Return error when running GetFailingTrustedAdvisorCheckResult",
			accountID: "12345",
			mockGetFailingTrustedAdvisorCheckResultsError: errors.New("Some API error"),
			expectedError: errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			mockAPIs.EXPECT().GetAccountID().Return(tc.accountID, tc.mockGetAccountIDError).MaxTimes(1)
			mockAPIs.EXPECT().GetFailingTrustedAdvisorCheckResults().Return(tc.mockGetFailingTrustedAdvisorCheckResultsResponse, tc.mockGetFailingTrustedAdvisorCheckResultsError).MaxTimes(1)

			comments := parseCommentsFile("../../test/data/comments.yaml")
			report := &TrustedAdvisorReport{}
			err := report.GetReport(mockAPIs, comments)

			assert.ElementsMatch(t, tc.expectedFindings, report.Findings)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestProcessTrustedAdvisorResults(t *testing.T) {
	testCases := []struct {
		name           string
		results        map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult
		account        string
		expectedOutput []trustedAdvisorFinding
	}{
		{
			name: "Return expected results",
			results: map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult{
				{
					Category: aws.String("cost_optimizing"),
					Description: aws.String(`Checks the Amazon Elastic Compute Cloud (Amazon EC2) instances that were running at any time during the last 14 days and alerts you if the daily CPU utilization was 10% or less and network I/O was 5 MB or less on 4 or more days. Running instances generate hourly usage charges. Although some scenarios can result in low utilization by design, you can often lower your costs by managing the number and size of your instances.
					<br><br>
					Estimated monthly savings are calculated by using the current usage rate for On-Demand Instances and the estimated number of days the instance might be underutilized. Actual savings will vary if you are using Reserved Instances or Spot Instances, or if the instance is not running for a full day. To get daily utilization data, download the report for this check.
					<br>
					<br>
					<b>Alert Criteria</b><br>
					Yellow: An instance had 10% or less daily average CPU utilization and 5 MB or less network I/O on at least 4 of the previous 14 days.<br>
					<br>
					<b>Recommended Action</b><br>
					Consider stopping or terminating instances that have low utilization, or scale the number of instances by using Auto Scaling. For more information, see <a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Stop_Start.html" target="_blank">Stop and Start Your Instance</a>, <a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html" target="_blank">Terminate Your Instance</a>, and <a href="http://docs.aws.amazon.com/AutoScaling/latest/DeveloperGuide/WhatIsAutoScaling.html" target="_blank">What is Auto Scaling?</a><br>
					<br>
					<b>Additional Resources</b><br>
					<a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-monitoring.html" target="_blank">Monitoring Amazon EC2</a><br>
					<a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AESDG-chapter-instancedata.html" target="_blank">Instance Metadata and User Data</a><br>
					<a href="http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/Welcome.html" target="_blank">Amazon CloudWatch Developer Guide</a><br>
					<a href="http://docs.aws.amazon.com/AutoScaling/latest/DeveloperGuide/WhatIsAutoScaling.html" target="_blank">Auto Scaling Developer Guide</a>`),
					Metadata: aws.StringSlice([]string{"Status", "Region", "instance-id", "Name"}),
					Name:     aws.String("Low Utilization Amazon EC2 Instances"),
				}: {
					Status: aws.String("warning"),
					FlaggedResources: []*support.TrustedAdvisorResourceDetail{
						{
							IsSuppressed: aws.Bool(false),
							Metadata: aws.StringSlice([]string{
								"Yellow",
								"us-east-1",
								"i-0123456789abcdefg",
								"k8s.example.com",
								"m5.2xlarge",
								"$276.48",
								"1.8%  3.34MB",
								"1.7%  3.29MB",
								"1.6%  3.29MB",
								"1.6%  3.32MB",
								"1.6%  3.28MB",
								"1.7%  3.41MB",
								"1.6%  3.43MB",
								"1.6%  3.47MB",
								"1.9%  3.34MB",
								"1.6%  3.29MB",
								"1.6%  3.40MB",
								"1.7%  3.48MB",
								"1.7%  3.51MB",
								"1.7%  3.43MB",
								"1.7%",
								"3.37MB",
								"14 days"},
							),
							Region:     aws.String("us-east-1"),
							ResourceId: aws.String("QtCJL9NshMFH8AHUBLdX_fvrnAOPSTpR-hzxk0YU4oI"),
							Status:     aws.String("warning"),
						},
						{
							IsSuppressed: aws.Bool(false),
							Metadata: aws.StringSlice([]string{
								"Yellow",
								"us-east-1",
								"i-abcdefg0123456789",
								"k8s.example.com",
								"m5.2xlarge",
								"$276.48",
								"1.0%  2.61MB",
								"1.1%  2.57MB",
								"1.0%  2.56MB",
								"1.0%  2.60MB",
								"1.0%  2.55MB",
								"1.0%  2.69MB",
								"1.0%  2.70MB",
								"1.0%  2.73MB",
								"1.1%  2.63MB",
								"1.0%  2.55MB",
								"1.0%  2.66MB",
								"1.0%  2.75MB",
								"1.0%  2.78MB",
								"1.0%  2.70MB",
								"1.0%",
								"2.65MB",
								"14 days"},
							),
							Region:     aws.String("us-east-1"),
							ResourceId: aws.String("M1nMGLq-DqEbS0jbaObJ1IXucGlQ_bcOOBBLQSVcCjU"),
							Status:     aws.String("warning"),
						},
						// This is just to test filtering out resources that have "Green" in their metadata
						{
							Metadata: aws.StringSlice([]string{
								"Green",
							},
							),
						},
					},
					ResourcesSummary: &support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(10),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(12),
						ResourcesSuppressed: aws.Int64(0),
					},
				},
				{
					Category: aws.String("security"),
					Description: aws.String(`Checks for your use of AWS Identity and Access Management (IAM). You can use IAM to create users, groups, and roles in AWS, and you can use permissions to control access to AWS resources.
					<br>
					<br>
					<b>Alert Criteria</b><br>
					Yellow: No IAM users have been created for this account.
					<br>
					<br>
					<b>Recommended Action</b><br>
					Create one or more IAM users and groups in your account. You can then create additional users whose permissions are limited to perform specific tasks in your AWS environment. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/IAMGettingStarted.html" target="_blank">Getting Started</a>.
					<br><br>
					<b>Additional Resources</b><br>
					<a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/IAM_Introduction.html" target="_blank">What Is IAM?</a>`),
					Name: aws.String("IAM Use"),
				}: {
					Status: aws.String("warning"),
					FlaggedResources: []*support.TrustedAdvisorResourceDetail{{
						IsSuppressed: aws.Bool(false),
						ResourceId:   aws.String("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"),
						Status:       aws.String("warning"),
					},
					},
					ResourcesSummary: &support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(1),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(1),
						ResourcesSuppressed: aws.Int64(0),
					},
				},
			},
			account: "111111111111",
			expectedOutput: []trustedAdvisorFinding{
				{
					AccountID:   "111111111111",
					Category:    "COST_OPTIMIZING",
					Name:        "Low Utilization Amazon EC2 Instances",
					Description: `Checks the Amazon Elastic Compute Cloud (Amazon EC2) instances that were running at any time during the last 14 days and alerts you if the daily CPU utilization was 10% or less and network I/O was 5 MB or less on 4 or more days. Running instances generate hourly usage charges. Although some scenarios can result in low utilization by design, you can often lower your costs by managing the number and size of your instances.`,
					Status:      "warning",
					ResourcesSummary: support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(10),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(12),
						ResourcesSuppressed: aws.Int64(0),
					},
					FlaggedResources: []string{"us-east-1/i-0123456789abcdefg", "us-east-1/i-abcdefg0123456789"},
					Comments:         "NEW_FINDING",
				}, {
					AccountID:   "111111111111",
					Category:    "SECURITY",
					Name:        "IAM Use",
					Description: "Checks for your use of AWS Identity and Access Management (IAM). You can use IAM to create users, groups, and roles in AWS, and you can use permissions to control access to AWS resources.",
					Status:      "warning",
					ResourcesSummary: support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(1),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(1),
						ResourcesSuppressed: aws.Int64(0),
					},
					FlaggedResources: []string{"NA"},
					Comments:         "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM",
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use comments file for testing
			comments := parseCommentsFile("../../test/data/comments.yaml")
			output := processTrustedAdvisorResults(tc.results, tc.account, comments)
			assert.ElementsMatch(t, tc.expectedOutput, output)
		})
	}
}
