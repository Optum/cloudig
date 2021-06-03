package cloudig

import (
	"errors"
	"io/ioutil"
	"sort"
	"testing"
	"time"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/configservice"
)

func TestAWSConfigGetReport(t *testing.T) {
	logrus.SetOutput(ioutil.Discard)
	testCases := []struct {
		name                          string
		accountID                     string
		complianceForConfigRules      map[string][]*configservice.EvaluationResult
		expectedFindings              []configFinding
		expectedGetAccountIDError     error
		ComplianceForConfigRulesError error
		expectedError                 error
	}{
		{
			name:      "Return expected report",
			accountID: "111111111111",
			complianceForConfigRules: map[string][]*configservice.EvaluationResult{
				"ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK": {
					{
						ComplianceType:        aws.String("COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK"),
								ResourceId:     aws.String("sg-00001"),
								ResourceType:   aws.String("AWS::EC2::SecurityGroup"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
					{
						ComplianceType:        aws.String("COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK"),
								ResourceId:     aws.String("sg-00002"),
								ResourceType:   aws.String("AWS::EC2::SecurityGroup"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
					{
						ComplianceType:        aws.String("NON_COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK"),
								ResourceId:     aws.String("sg-00003"),
								ResourceType:   aws.String("AWS::EC2::SecurityGroup"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
				},
				"S3_BUCKET_LOGGING_ENABLED": {
					{
						ComplianceType:        aws.String("COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("S3_BUCKET_LOGGING_ENABLED"),
								ResourceId:     aws.String("222222222222-tfstate-stage"),
								ResourceType:   aws.String("AWS::S3::Bucket"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
					{
						ComplianceType:        aws.String("NON_COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("S3_BUCKET_LOGGING_ENABLED"),
								ResourceId:     aws.String("dig-log-bucket-nonprod-222222222222"),
								ResourceType:   aws.String("AWS::S3::Bucket"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
				},
			},
			expectedFindings: []configFinding{
				{
					AccountID:        "111111111111",
					RuleName:         "ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK",
					Status:           "NON_COMPLIANT",
					FlaggedResources: map[string][]string{"AWS::EC2::SecurityGroup": {"sg-00003"}},
					Comments:         "NEW_FINDING",
				},
				{
					AccountID:        "111111111111",
					RuleName:         "S3_BUCKET_LOGGING_ENABLED",
					Status:           "NON_COMPLIANT",
					FlaggedResources: map[string][]string{"AWS::S3::Bucket": {"dig-log-bucket-nonprod-222222222222"}},
					Comments:         "NEW_FINDING",
				},
			},
			expectedGetAccountIDError:     nil,
			ComplianceForConfigRulesError: nil,
			expectedError:                 nil,
		},
		{
			name:                      "Return error when getting AccountID",
			accountID:                 "",
			expectedGetAccountIDError: errors.New("Some API error"),
			expectedError:             errors.New("Some API error"),
		},
		{
			name:                          "Return error when getting Compliance Details for Config Rules",
			accountID:                     "1234",
			ComplianceForConfigRulesError: errors.New("Some API error"),
			expectedError:                 errors.New("Some API error"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			mockAPIs.EXPECT().GetAccountID().Return(tc.accountID, tc.expectedGetAccountIDError).MaxTimes(1)
			mockAPIs.EXPECT().GetNonComplaintConfigRules().Return(tc.complianceForConfigRules, tc.ComplianceForConfigRulesError).MaxTimes(1)
			// Use comments file for testing
			comments := parseCommentsFile("../../test/data/comments.yaml")
			report := ConfigReport{}
			err := report.GetReport(mockAPIs, comments)

			sort.SliceStable(tc.expectedFindings, func(i, j int) bool { return tc.expectedFindings[i].RuleName < tc.expectedFindings[j].RuleName })
			sort.SliceStable(report.Findings, func(i, j int) bool { return report.Findings[i].RuleName < report.Findings[j].RuleName })
			assert.Equal(t, tc.expectedFindings, report.Findings)
			assert.Equal(t, tc.expectedError, err)
		})
	}

}

func TestProcessConfigResults(t *testing.T) {
	logrus.SetOutput(ioutil.Discard)
	testCases := []struct {
		name           string
		results        map[string][]*configservice.EvaluationResult
		finding        configFinding
		expectedOutput []configFinding
	}{
		{
			name: "Return correct results",
			results: map[string][]*configservice.EvaluationResult{
				"ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK": {
					{
						ComplianceType:        aws.String("COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK"),
								ResourceId:     aws.String("sg-00001"),
								ResourceType:   aws.String("AWS::EC2::SecurityGroup"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},

					{
						ComplianceType:        aws.String("COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK"),
								ResourceId:     aws.String("sg-00002"),
								ResourceType:   aws.String("AWS::EC2::SecurityGroup"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
					{
						ComplianceType:        aws.String("NON_COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK"),
								ResourceId:     aws.String("sg-00003"),
								ResourceType:   aws.String("AWS::EC2::SecurityGroup"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
				},
				"S3_BUCKET_LOGGING_ENABLED": {
					{
						ComplianceType:        aws.String("COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("S3_BUCKET_LOGGING_ENABLED"),
								ResourceId:     aws.String("222222222222-tfstate-stage"),
								ResourceType:   aws.String("AWS::S3::Bucket"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
					{
						ComplianceType:        aws.String("NON_COMPLIANT"),
						ConfigRuleInvokedTime: timeHelper(2018, time.December, 21, 8, 38, 52, 0, time.UTC),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("S3_BUCKET_LOGGING_ENABLED"),
								ResourceId:     aws.String("dig-log-bucket-nonprod-222222222222"),
								ResourceType:   aws.String("AWS::S3::Bucket"),
							},
							OrderingTimestamp: timeHelper(2018, time.December, 21, 8, 38, 36, 0, time.UTC),
						},
						ResultRecordedTime: timeHelper(2018, time.December, 21, 8, 38, 53, 0, time.UTC),
					},
				},
			},
			finding: configFinding{AccountID: "111111111111"},
			expectedOutput: []configFinding{
				{
					AccountID:        "111111111111",
					RuleName:         "S3_BUCKET_LOGGING_ENABLED",
					Status:           "NON_COMPLIANT",
					FlaggedResources: map[string][]string{"AWS::S3::Bucket": {"dig-log-bucket-nonprod-222222222222"}},
					Comments:         "NEW_FINDING",
				},
				{
					AccountID:        "111111111111",
					RuleName:         "ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK",
					Status:           "NON_COMPLIANT",
					FlaggedResources: map[string][]string{"AWS::EC2::SecurityGroup": {"sg-00003"}},
					Comments:         "NEW_FINDING",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use comments file for testing
			comments := parseCommentsFile("../../test/data/comments.yaml")
			output := processConfigResults(tc.results, tc.finding, comments)
			assert.ElementsMatch(t, tc.expectedOutput, output)
		})
	}
}

func timeHelper(year int, month time.Month, day, hour, min, sec, nsec int, loc *time.Location) *time.Time {
	t := time.Date(year, month, day, hour, min, sec, nsec, loc)
	return &t
}
