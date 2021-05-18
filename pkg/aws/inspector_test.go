package aws

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/inspector"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/Optum/cloudig/pkg/mocks"
)

func TestGetResourceGroupTags(t *testing.T) {
	type args struct {
		assessmentTargetArn string
	}
	testCases := []struct {
		name                                 string
		input                                args
		describeAssessmentTargetsAPIResponse *inspector.DescribeAssessmentTargetsOutput
		describeResourceGroupsAPIResponse    *inspector.DescribeResourceGroupsOutput
		expectedOutput                       map[string]string
		expectedError                        error
	}{
		{
			name: "Return expected resource group tags",
			input: args{
				assessmentTargetArn: "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF",
			},
			describeAssessmentTargetsAPIResponse: &inspector.DescribeAssessmentTargetsOutput{
				AssessmentTargets: []*inspector.AssessmentTarget{
					{
						Arn:              aws.String("arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF"),
						Name:             aws.String("k8s_cluster"),
						ResourceGroupArn: aws.String("arn:aws:inspector:us-east-1:111111111111:resourcegroup/0-GFvUHPhY"),
					},
				},
			},
			describeResourceGroupsAPIResponse: &inspector.DescribeResourceGroupsOutput{
				ResourceGroups: []*inspector.ResourceGroup{
					{
						Arn: aws.String("arn:aws:inspector:us-east-1:111111111111:resourcegroup/0-GFvUHPhY"),
						Tags: []*inspector.ResourceGroupTag{
							{
								Key:   aws.String("dig-owned"),
								Value: aws.String("True"),
							},
							{
								Key:   aws.String("aws_inspector"),
								Value: aws.String("true"),
							},
							{
								Key:   aws.String("terraform"),
								Value: aws.String("True"),
							},
						},
					},
				},
			},
			expectedOutput: map[string]string{
				"dig-owned":     "True",
				"aws_inspector": "true",
				"terraform":     "True",
			},
			expectedError: nil,
		},
		{
			name: "Error response",
			input: args{
				assessmentTargetArn: "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF",
			},
			expectedOutput: nil,
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockInspectorAPI := mocks.NewMockInspectorAPI(mockCtrl)
			mockInspectorAPI.EXPECT().DescribeAssessmentTargets(gomock.Any()).Return(tc.describeAssessmentTargetsAPIResponse, tc.expectedError).MaxTimes(1)
			mockInspectorAPI.EXPECT().DescribeResourceGroups(gomock.Any()).Return(tc.describeResourceGroupsAPIResponse, tc.expectedError).MaxTimes(1)

			client := &Client{
				Inspector: mockInspectorAPI,
			}

			output, err := client.GetResourceGroupTags(tc.input.assessmentTargetArn)
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
func TestGetMostRecentAssessmentRunInfo(t *testing.T) {
	testCases := []struct {
		name                                   string
		listAssessmentTemplatesAPIResponse     *inspector.ListAssessmentTemplatesOutput
		describeAssessmentTemplatesAPIResponse *inspector.DescribeAssessmentTemplatesOutput
		expectedOutput                         []map[string]string
		expectedError                          error
	}{
		{
			name: "Get assessment template info correctly",
			listAssessmentTemplatesAPIResponse: &inspector.ListAssessmentTemplatesOutput{
				AssessmentTemplateArns: aws.StringSlice([]string{"arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW/template/0-qLRbgV2x", "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF/template/0-eLtPoQf3"}),
			},
			describeAssessmentTemplatesAPIResponse: &inspector.DescribeAssessmentTemplatesOutput{
				AssessmentTemplates: []*inspector.AssessmentTemplate{
					{
						Arn:                  aws.String("arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW/template/0-qLRbgV2x"),
						AssessmentRunCount:   aws.Int64(1),
						AssessmentTargetArn:  aws.String("arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW"),
						LastAssessmentRunArn: aws.String("arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW/template/0-qLRbgV2x/run/0-gKfIrDIK"),
						Name:                 aws.String("test-once-dev"),
						RulesPackageArns:     aws.StringSlice([]string{"arn:aws:inspector:us-east-1:222222222222:rulespackage/0-gEjTy7T7", "arn:aws:inspector:us-east-1:222222222222:rulespackage/0-rExsr2X8", "arn:aws:inspector:us-east-1:222222222222:rulespackage/0-R01qwB5Q"}),
					},
					{
						Arn:                  aws.String("arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF/template/0-eLtPoQf3"),
						AssessmentRunCount:   aws.Int64(23),
						AssessmentTargetArn:  aws.String("arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF"),
						LastAssessmentRunArn: aws.String("arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF/template/0-eLtPoQf3/run/0-8Wf02Drc"),
						Name:                 aws.String("k8s_weekly_scan"),
						RulesPackageArns: aws.StringSlice([]string{
							"arn:aws:inspector:us-east-1:222222222222:rulespackage/0-gEjTy7T7",
							"arn:aws:inspector:us-east-1:222222222222:rulespackage/0-rExsr2X8",
							"arn:aws:inspector:us-east-1:222222222222:rulespackage/0-PmNV0Tcd",
							"arn:aws:inspector:us-east-1:222222222222:rulespackage/0-R01qwB5Q",
						}),
					},
				},
			},
			expectedOutput: []map[string]string{
				{
					"templateName": "test-once-dev",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW/template/0-qLRbgV2x/run/0-gKfIrDIK",
				},
				{
					"templateName": "k8s_weekly_scan",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF/template/0-eLtPoQf3/run/0-8Wf02Drc",
				},
			},
			expectedError: nil,
		},
		{
			name:           "Error response",
			expectedOutput: nil,
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockInspectorAPI := mocks.NewMockInspectorAPI(mockCtrl)
			mockInspectorAPI.EXPECT().ListAssessmentTemplates(&inspector.ListAssessmentTemplatesInput{}).Return(tc.listAssessmentTemplatesAPIResponse, tc.expectedError).MaxTimes(1)
			mockInspectorAPI.EXPECT().DescribeAssessmentTemplates(gomock.Any()).Return(tc.describeAssessmentTemplatesAPIResponse, tc.expectedError).MaxTimes(1)

			client := &Client{
				Inspector: mockInspectorAPI,
			}

			output, err := client.GetMostRecentAssessmentRunInfo()
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestGenerateReport(t *testing.T) {
	type args struct {
		assessmentRunArn string
		reportFormat     string
		reportType       string
	}
	testCases := []struct {
		name           string
		input          *args
		apiResponse    *inspector.GetAssessmentReportOutput
		expectedOutput string
		expectedError  error
	}{
		{
			name: "Get HTML Inspector report",
			input: &args{
				assessmentRunArn: "arn:aws:inspector:us-east-1:012345678910:target/0-E70Tx7xF/template/0-rzwwKHOj/run/0-YIoTczu6",
				reportFormat:     "HTML",
				reportType:       "FULL",
			},
			apiResponse: &inspector.GetAssessmentReportOutput{
				Status: aws.String("COMPLETED"),
				Url:    aws.String("https://inspector-temp-reports-prod-us-east-1.s3.amazonaws.com/arn%3Aaws%3Ainspector%3Aus-east-1%3A012345678910%3Atarget/0-E70Tx7xF/template/0-rzwwKHOj/run/0-YIoTczu6-full-report.html?response-content-type=text%2Fhtml&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20200102T141203Z&X-Amz-SignedHeaders=host&X-Amz-Expires=900&X-Amz-Credential=AKIAUTGOFMZ6SBI6BDMH%2F20200102%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=889649d423f4158344daf6a4ee28cee000e9f52dda08c71beaf0b6a8226e6625"),
			},
			expectedOutput: "https://inspector-temp-reports-prod-us-east-1.s3.amazonaws.com/arn%3Aaws%3Ainspector%3Aus-east-1%3A012345678910%3Atarget/0-E70Tx7xF/template/0-rzwwKHOj/run/0-YIoTczu6-full-report.html?response-content-type=text%2Fhtml&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20200102T141203Z&X-Amz-SignedHeaders=host&X-Amz-Expires=900&X-Amz-Credential=AKIAUTGOFMZ6SBI6BDMH%2F20200102%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=889649d423f4158344daf6a4ee28cee000e9f52dda08c71beaf0b6a8226e6625",
			expectedError:  nil,
		},
		{
			name: "Error response",
			input: &args{
				assessmentRunArn: "arn:aws:inspector:us-east-1:012345678910:target/0-E70Tx7xF/template/0-rzwwKHOj/run/0-YIoTczu6",
				reportFormat:     "HTML",
				reportType:       "FULL",
			},
			apiResponse:    &inspector.GetAssessmentReportOutput{},
			expectedOutput: "",
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockInspectorAPI := mocks.NewMockInspectorAPI(mockCtrl)
			mockInspectorAPI.EXPECT().GetAssessmentReport(
				&inspector.GetAssessmentReportInput{
					AssessmentRunArn: aws.String(tc.input.assessmentRunArn),
					ReportFileFormat: aws.String(tc.input.reportFormat),
					ReportType:       aws.String(tc.input.reportType),
				},
			).Return(tc.apiResponse, tc.expectedError)
			client := &Client{
				Inspector: mockInspectorAPI,
			}

			output, err := client.GenerateReport(tc.input.assessmentRunArn, tc.input.reportFormat, tc.input.reportType)
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
