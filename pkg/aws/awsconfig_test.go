package aws

import (
	"errors"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetNonComplaintConfigRules(t *testing.T) {
	testCases := []struct {
		name                                           string
		mockedDescribeComplianceByConfigRuleResponse   []*configservice.DescribeComplianceByConfigRuleOutput
		mockedGetComplianceDetailsByConfigRuleResponse []*configservice.GetComplianceDetailsByConfigRuleOutput
		mockedDescribeComplianceByConfigRuleError      error
		mockedGetComplianceDetailsByConfigRuleError    error
		expectedOutput                                 map[string][]*configservice.EvaluationResult
		expectedError                                  error
	}{
		{
			name: "Empty response",
			mockedDescribeComplianceByConfigRuleResponse: []*configservice.DescribeComplianceByConfigRuleOutput{{}},
			expectedOutput: map[string][]*configservice.EvaluationResult{},
			expectedError:  nil,
		},
		{
			name: "Populated response",
			mockedDescribeComplianceByConfigRuleResponse: []*configservice.DescribeComplianceByConfigRuleOutput{
				{
					ComplianceByConfigRules: []*configservice.ComplianceByConfigRule{
						{
							Compliance: &configservice.Compliance{
								ComplianceType: aws.String("NON_COMPLIANT"),
							},
							ConfigRuleName: aws.String("CUSTOM_UNATTACHED_ENCRYPTED_VOLUMES"),
						},
						{
							Compliance: &configservice.Compliance{
								ComplianceType: aws.String("NON_COMPLIANT"),
							},
							ConfigRuleName: aws.String("S3_BUCKET_PUBLIC_WRITE_PROHIBITED"),
						},
					},
					NextToken: aws.String("dsfsdfdsfsdf"),
				},
				{
					ComplianceByConfigRules: []*configservice.ComplianceByConfigRule{
						{
							Compliance: &configservice.Compliance{
								ComplianceType: aws.String("COMPLIANT"),
							},
							ConfigRuleName: aws.String("S3_BUCKET_OPEN"),
						},
						{
							Compliance: &configservice.Compliance{
								ComplianceType: aws.String("INSUFFICIENT_DATA"),
							},
							ConfigRuleName: aws.String("EC2_SSH_OPEN_TO_INTERNET"),
						},
					},
				},
			},
			mockedGetComplianceDetailsByConfigRuleResponse: []*configservice.GetComplianceDetailsByConfigRuleOutput{
				{
					EvaluationResults: []*configservice.EvaluationResult{
						{
							Annotation:     aws.String("Volume is encrypted and attached"),
							ComplianceType: aws.String("COMPLIANT"),
							EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
								EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
									ConfigRuleName: aws.String("CUSTOM_UNATTACHED_ENCRYPTED_VOLUMES"),
									ResourceId:     aws.String("vol-0020f9b701caa2314"),
									ResourceType:   aws.String("AWS::EC2::Volume"),
								},
							},
						},
						{
							Annotation:     aws.String("Volume is encrypted and attached"),
							ComplianceType: aws.String("NON_COMPLIANT"),
							EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
								EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
									ConfigRuleName: aws.String("CUSTOM_UNATTACHED_ENCRYPTED_VOLUMES"),
									ResourceId:     aws.String("vol-f0u5n6u3s4e4e5it"),
									ResourceType:   aws.String("AWS::EC2::Volume"),
								},
							},
						},
					},
				},
				{
					EvaluationResults: []*configservice.EvaluationResult{
						{
							Annotation:     aws.String("public write prohibited"),
							ComplianceType: aws.String("NON_COMPLIANT"),
							EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
								EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
									ConfigRuleName: aws.String("S3_BUCKET_PUBLIC_WRITE_PROHIBITED"),
									ResourceId:     aws.String("sing-dong-bucket"),
									ResourceType:   aws.String("AWS::S3::Bucket"),
								},
							},
						},
					},
				},
			},
			expectedOutput: map[string][]*configservice.EvaluationResult{
				"CUSTOM_UNATTACHED_ENCRYPTED_VOLUMES": {
					{
						Annotation:     aws.String("Volume is encrypted and attached"),
						ComplianceType: aws.String("COMPLIANT"),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("CUSTOM_UNATTACHED_ENCRYPTED_VOLUMES"),
								ResourceId:     aws.String("vol-0020f9b701caa2314"),
								ResourceType:   aws.String("AWS::EC2::Volume"),
							},
						},
					},
					{
						Annotation:     aws.String("Volume is encrypted and attached"),
						ComplianceType: aws.String("NON_COMPLIANT"),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("CUSTOM_UNATTACHED_ENCRYPTED_VOLUMES"),
								ResourceId:     aws.String("vol-f0u5n6u3s4e4e5it"),
								ResourceType:   aws.String("AWS::EC2::Volume"),
							},
						},
					},
				},
				"S3_BUCKET_PUBLIC_WRITE_PROHIBITED": {
					{
						Annotation:     aws.String("public write prohibited"),
						ComplianceType: aws.String("NON_COMPLIANT"),
						EvaluationResultIdentifier: &configservice.EvaluationResultIdentifier{
							EvaluationResultQualifier: &configservice.EvaluationResultQualifier{
								ConfigRuleName: aws.String("S3_BUCKET_PUBLIC_WRITE_PROHIBITED"),
								ResourceId:     aws.String("sing-dong-bucket"),
								ResourceType:   aws.String("AWS::S3::Bucket"),
							},
						},
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "error response from DescribeComplianceByConfigRule",
			mockedDescribeComplianceByConfigRuleResponse:   nil,
			mockedGetComplianceDetailsByConfigRuleResponse: nil,
			mockedDescribeComplianceByConfigRuleError:      errors.New("some error"),
			expectedOutput: nil,
			expectedError:  errors.New("some error"),
		},
		{
			name: "error response from GetComplianceDetailsByConfigRule",
			mockedDescribeComplianceByConfigRuleResponse: []*configservice.DescribeComplianceByConfigRuleOutput{
				{
					ComplianceByConfigRules: []*configservice.ComplianceByConfigRule{
						{
							Compliance: &configservice.Compliance{
								ComplianceType: aws.String("NON_COMPLIANT"),
							},
							ConfigRuleName: aws.String("CUSTOM_UNATTACHED_ENCRYPTED_VOLUMES"),
						},
					},
				},
			},
			mockedGetComplianceDetailsByConfigRuleResponse: nil,
			mockedGetComplianceDetailsByConfigRuleError:    errors.New("some error"),
			expectedOutput: nil,
			expectedError:  errors.New("some error"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockConfigServiceAPI := mocks.NewMockConfigServiceAPI(mockCtrl)

			if len(tc.mockedDescribeComplianceByConfigRuleResponse) > 0 {
				for _, resp := range tc.mockedDescribeComplianceByConfigRuleResponse {
					mockConfigServiceAPI.EXPECT().DescribeComplianceByConfigRule(gomock.Any()).Return(resp, tc.mockedDescribeComplianceByConfigRuleError).MaxTimes(1)
				}
			} else {
				mockConfigServiceAPI.EXPECT().DescribeComplianceByConfigRule(gomock.Any()).Return(nil, tc.mockedDescribeComplianceByConfigRuleError).MaxTimes(1)
			}

			if len(tc.mockedGetComplianceDetailsByConfigRuleResponse) > 0 {
				for _, resp := range tc.mockedGetComplianceDetailsByConfigRuleResponse {
					mockConfigServiceAPI.EXPECT().GetComplianceDetailsByConfigRule(gomock.Any()).Return(resp, tc.mockedGetComplianceDetailsByConfigRuleError).MaxTimes(1)
				}
			} else {
				mockConfigServiceAPI.EXPECT().GetComplianceDetailsByConfigRule(gomock.Any()).Return(nil, tc.mockedGetComplianceDetailsByConfigRuleError).MaxTimes(1)
			}

			client := &Client{
				AWSConfig: mockConfigServiceAPI,
			}

			output, err := client.GetNonComplaintConfigRules()
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
