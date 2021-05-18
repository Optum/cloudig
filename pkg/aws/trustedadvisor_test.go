package aws

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/support"
)

func TestGetFailingTrustedAdvisorCheckResults(t *testing.T) {
	testCases := []struct {
		name                                          string
		mockDescribeTrustedAdvisorChecksResponse      *support.DescribeTrustedAdvisorChecksOutput
		mockDescribeTrustedAdvisorCheckResultResponse []*support.DescribeTrustedAdvisorCheckResultOutput
		mockDescribeTrustedAdvisorChecksError         error
		mockDescribeTrustedAdvisorCheckResultError    error
		expectedOutput                                map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult
		expectedError                                 error
	}{
		{
			name: "Get failing results for a TrustedAdvisor checks",
			mockDescribeTrustedAdvisorChecksResponse: &support.DescribeTrustedAdvisorChecksOutput{
				Checks: []*support.TrustedAdvisorCheckDescription{
					{
						Category:    aws.String("cost_optimizing"),
						Description: aws.String("Checks for Elastic IP addresses (EIPs) that are not associated with a running Amazon Elastic Compute Cloud (Amazon EC2) instance. EIPs are static IP addresses designed for dynamic cloud computing. Unlike traditional static IP addresses, EIPs can mask the failure of an instance or Availability Zone by remapping a public IP address to another instance in your account. A nominal charge is imposed for an EIP that is not associated with a running instance.<br>\n<br>\n<b>Alert Criteria</b><br>\nYellow: An allocated Elastic IP address (EIP) is not associated with a running Amazon EC2 instance.<br>\n<br>\n<b>Recommended Action</b><br>\nAssociate the EIP with a running active instance, or release the unassociated EIP. For more information, see <a href=\"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-eips-associating-different\" target=\"_blank\">Associating an Elastic IP Address with a Different Running Instance</a> and <a href=\"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-eips-releasing\" target=\"_blank\">Releasing an Elastic IP Address</a>.<br>\n<br>\n<b>Additional Resources</b><br>\n<a href=\"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html\" target=\"_blank\">Elastic IP Addresses</a>"),
						Id:          aws.String("Z4AUBRNSmz"),
						Metadata:    aws.StringSlice([]string{"Status", "Region", "IP Address"}),
						Name:        aws.String("Unassociated Elastic IP Addresses"),
					},
					{
						Category:    aws.String("security"),
						Description: aws.String("Checks security groups for rules that allow unrestricted access (0.0.0.0/0) to specific ports. Unrestricted access increases opportunities for malicious activity (hacking, denial-of-service attacks, loss of data). The ports with highest risk are flagged red, and those with less risk are flagged yellow. Ports flagged green are typically used by applications that require unrestricted access, such as HTTP and SMTP.\n<br>\nIf you have intentionally configured your security groups in this manner, we recommend using additional security measures to secure your infrastructure (such as IP tables).\n<br>\n<br>\n<b>Alert Criteria</b>\n<br>\nGreen: Access to port 80, 25, 443, or 465 is unrestricted.<br>\nRed: Access to port 20, 21, 1433, 1434, 3306, 3389, 4333, 5432, or 5500 is unrestricted.<br>\nYellow: Access to any other port is unrestricted.\n<br>\n<br>\n<b>Recommended Action</b>\n<br>\nRestrict access to only those IP addresses that require it. To restrict access to a specific IP address, set the suffix to /32 (for example, 192.0.2.10/32). Be sure to delete overly permissive rules after creating rules that are more restrictive.<br>\n<br>\n<b>Additional Resources</b><br>\n<a href=\"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html\" target=\"_blank\">Amazon EC2 Security Groups</a><br>\n<a href=\"http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers\" target=\"_blank\">List of TCP and UDP port numbers</a> (Wikipedia)<br>\n<a href=\"http://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing\" target=\"_blank\">Classless Inter-Domain Routing</a> (Wikipedia)"),
						Id:          aws.String("HCP4007jGY"),
						Metadata: aws.StringSlice([]string{
							"Region",
							"Security Group Name",
							"Security Group ID",
							"Protocol",
						}),
						Name: aws.String("Security Groups - Specific Ports Unrestricted"),
					},
				},
			},
			mockDescribeTrustedAdvisorCheckResultResponse: []*support.DescribeTrustedAdvisorCheckResultOutput{
				{
					Result: &support.TrustedAdvisorCheckResult{
						CheckId: aws.String("Z4AUBRNSmz"),
						ResourcesSummary: &support.TrustedAdvisorResourcesSummary{
							ResourcesFlagged:    aws.Int64(0),
							ResourcesIgnored:    aws.Int64(0),
							ResourcesProcessed:  aws.Int64(7),
							ResourcesSuppressed: aws.Int64(0),
						},
						Status: aws.String("ok"),
					},
				},
				{
					Result: &support.TrustedAdvisorCheckResult{
						CheckId: aws.String("HCP4007jGY"),
						ResourcesSummary: &support.TrustedAdvisorResourcesSummary{
							ResourcesFlagged:    aws.Int64(0),
							ResourcesIgnored:    aws.Int64(0),
							ResourcesProcessed:  aws.Int64(3),
							ResourcesSuppressed: aws.Int64(0),
						},
						FlaggedResources: []*support.TrustedAdvisorResourceDetail{
							{
								IsSuppressed: aws.Bool(false),
								Metadata: aws.StringSlice([]string{
									"Yellow",
									"us-east-1",
									"My-test-SG",
									"sg-passmeifyoucan",
									"tcp",
								},
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
									"My-test-SG",
									"sg-allarewelcome",
									"udp"},
								),
								Region:     aws.String("us-east-1"),
								ResourceId: aws.String("M1nMGLq-DqEbS0jbaObJ1IXucGlQ_shfjksdkflsdfd"),
								Status:     aws.String("warning"),
							},
						},
						Status: aws.String("warning"),
					},
				},
			},
			expectedOutput: map[*support.TrustedAdvisorCheckDescription]*support.TrustedAdvisorCheckResult{
				{
					Category:    aws.String("security"),
					Description: aws.String("Checks security groups for rules that allow unrestricted access (0.0.0.0/0) to specific ports. Unrestricted access increases opportunities for malicious activity (hacking, denial-of-service attacks, loss of data). The ports with highest risk are flagged red, and those with less risk are flagged yellow. Ports flagged green are typically used by applications that require unrestricted access, such as HTTP and SMTP.\n<br>\nIf you have intentionally configured your security groups in this manner, we recommend using additional security measures to secure your infrastructure (such as IP tables).\n<br>\n<br>\n<b>Alert Criteria</b>\n<br>\nGreen: Access to port 80, 25, 443, or 465 is unrestricted.<br>\nRed: Access to port 20, 21, 1433, 1434, 3306, 3389, 4333, 5432, or 5500 is unrestricted.<br>\nYellow: Access to any other port is unrestricted.\n<br>\n<br>\n<b>Recommended Action</b>\n<br>\nRestrict access to only those IP addresses that require it. To restrict access to a specific IP address, set the suffix to /32 (for example, 192.0.2.10/32). Be sure to delete overly permissive rules after creating rules that are more restrictive.<br>\n<br>\n<b>Additional Resources</b><br>\n<a href=\"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html\" target=\"_blank\">Amazon EC2 Security Groups</a><br>\n<a href=\"http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers\" target=\"_blank\">List of TCP and UDP port numbers</a> (Wikipedia)<br>\n<a href=\"http://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing\" target=\"_blank\">Classless Inter-Domain Routing</a> (Wikipedia)"),
					Id:          aws.String("HCP4007jGY"),
					Metadata: aws.StringSlice([]string{
						"Region",
						"Security Group Name",
						"Security Group ID",
						"Protocol",
					}),
					Name: aws.String("Security Groups - Specific Ports Unrestricted"),
				}: {
					CheckId: aws.String("HCP4007jGY"),
					ResourcesSummary: &support.TrustedAdvisorResourcesSummary{
						ResourcesFlagged:    aws.Int64(0),
						ResourcesIgnored:    aws.Int64(0),
						ResourcesProcessed:  aws.Int64(3),
						ResourcesSuppressed: aws.Int64(0),
					},
					FlaggedResources: []*support.TrustedAdvisorResourceDetail{
						{
							IsSuppressed: aws.Bool(false),
							Metadata: aws.StringSlice([]string{
								"Yellow",
								"us-east-1",
								"My-test-SG",
								"sg-passmeifyoucan",
								"tcp",
							},
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
								"My-test-SG",
								"sg-allarewelcome",
								"udp"},
							),
							Region:     aws.String("us-east-1"),
							ResourceId: aws.String("M1nMGLq-DqEbS0jbaObJ1IXucGlQ_shfjksdkflsdfd"),
							Status:     aws.String("warning"),
						},
					},
					Status: aws.String("warning"),
				},
			},
		},
		{
			name:                                     "error from DescribeTrustedAdvisorChecks",
			mockDescribeTrustedAdvisorChecksResponse: nil,
			mockDescribeTrustedAdvisorChecksError:    errors.New("bad error"),
			expectedOutput:                           nil,
			expectedError:                            errors.New("bad error"),
		},
		{
			name: "error from DescribeTrustedAdvisorCheckResult",
			mockDescribeTrustedAdvisorChecksResponse: &support.DescribeTrustedAdvisorChecksOutput{
				Checks: []*support.TrustedAdvisorCheckDescription{
					{
						Category:    aws.String("cost_optimizing"),
						Description: aws.String("Checks for Elastic IP addresses (EIPs) that are not associated with a running Amazon Elastic Compute Cloud (Amazon EC2) instance. EIPs are static IP addresses designed for dynamic cloud computing. Unlike traditional static IP addresses, EIPs can mask the failure of an instance or Availability Zone by remapping a public IP address to another instance in your account. A nominal charge is imposed for an EIP that is not associated with a running instance.<br>\n<br>\n<b>Alert Criteria</b><br>\nYellow: An allocated Elastic IP address (EIP) is not associated with a running Amazon EC2 instance.<br>\n<br>\n<b>Recommended Action</b><br>\nAssociate the EIP with a running active instance, or release the unassociated EIP. For more information, see <a href=\"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-eips-associating-different\" target=\"_blank\">Associating an Elastic IP Address with a Different Running Instance</a> and <a href=\"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-eips-releasing\" target=\"_blank\">Releasing an Elastic IP Address</a>.<br>\n<br>\n<b>Additional Resources</b><br>\n<a href=\"http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html\" target=\"_blank\">Elastic IP Addresses</a>"),
						Id:          aws.String("Z4AUBRNSmz"),
						Metadata:    aws.StringSlice([]string{"Status", "Region", "IP Address"}),
						Name:        aws.String("Unassociated Elastic IP Addresses"),
					},
				},
			},
			mockDescribeTrustedAdvisorCheckResultResponse: nil,
			mockDescribeTrustedAdvisorCheckResultError:    errors.New("bad error"),
			expectedOutput: nil,
			expectedError:  errors.New("bad error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockSupportAPI := mocks.NewMockSupportAPI(mockCtrl)

			mockSupportAPI.EXPECT().DescribeTrustedAdvisorChecks(gomock.Any()).Return(tc.mockDescribeTrustedAdvisorChecksResponse, tc.mockDescribeTrustedAdvisorChecksError).MaxTimes(1)
			if tc.mockDescribeTrustedAdvisorChecksResponse != nil &&
				tc.mockDescribeTrustedAdvisorCheckResultResponse != nil &&
				len(tc.mockDescribeTrustedAdvisorChecksResponse.Checks) > 0 {
				for i := range tc.mockDescribeTrustedAdvisorChecksResponse.Checks {
					mockSupportAPI.EXPECT().DescribeTrustedAdvisorCheckResult(gomock.Any()).Return(tc.mockDescribeTrustedAdvisorCheckResultResponse[i], tc.mockDescribeTrustedAdvisorCheckResultError).MaxTimes(1)
				}
			} else {
				mockSupportAPI.EXPECT().DescribeTrustedAdvisorCheckResult(gomock.Any()).Return(nil, tc.mockDescribeTrustedAdvisorCheckResultError).MaxTimes(1)
			}
			client := &Client{
				TrustedAdvisor: mockSupportAPI,
			}
			output, err := client.GetFailingTrustedAdvisorCheckResults()
			reflect.DeepEqual(tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}

}
