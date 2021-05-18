package cloudig

import (
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
)

func TestGetComments(t *testing.T) {
	comments := []Comments{
		{
			AccountID:  "TEST_ACCOUNT1",
			TAFindings: []map[string]string{{"SECURITY-IAM_Use": "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM"}, {"FAULT_TOLERANCE-Amazon_EBS_Snapshots": "**EXCEPTION:** We do not persist any critical data on EC2 attached EBS. Data present in these disks are ephemeral in nature"}},
			ConfigFindings: []map[string]string{
				{"IAM_POLICY_BLACKLISTED_CHECK": "**EXCEPTION:** Removed the AdminstratorAccess policy since the default AWS_*_Admins uses the policy. Future enhancement would be to create a Custom Rule that no other Role can use the AdmnistratorAccess policy besides the AWS_*_Admins"},
				{"ATTACHED_INTERNET_GATEWAY_CHECK": "**EXCEPTION:** Flags VPCs that have an Internet Gateway attached, Most of our VPC requires IGW enabled in Public subnets as they are web application open to Internet. Better RULE would be to check VPC with all of its SUBNET open to IGW"},
			},
			HealthReportFindings: []map[string]string{{"AWS_RDS_OPERATIONAL_NOTIFICATION": "**EXCEPTION:** Already taken care."}},
		},
		{
			AccountID: "TEST_ACCOUNT2",
			TAFindings: []map[string]string{
				{"SECURITY-IAM_Use": "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM"},
				{"FAULT_TOLERANCE-Amazon_EBS_Snapshots": "**EXCEPTION:** We do not persist any critical data on EC2 attached EBS. Data present in these disks are ephemeral in nature"},
			},
			ConfigFindings: []map[string]string{{"IAM_POLICY_BLACKLISTED_CHECK": "**EXCEPTION:** Removed the AdminstratorAccess policy since the default AWS_*_Admins uses the policy. Future enhancement would be to create a Custom Rule that no other Role can use the AdmnistratorAccess policy besides the AWS_*_Admins"},
				{"ATTACHED_INTERNET_GATEWAY_CHECK": "**EXCEPTION:** Flags VPCs that have an Internet Gateway attached, Most of our VPC requires IGW enabled in Public subnets as they are web application open to Internet. Better RULE would be to check VPC with all of its SUBNET open to IGW"},
			},
			InspectorReportFindings: []map[string]string{{"CIS_Operating_System_Security_Configuration_Benchmarks-1.0": "**EXCEPTION:** Description here"}},
			ImageScanFindings: []map[string]string{
				{"333333333333.dkr.ecr.us-east-1.amazonaws.com/admin/kube-state-metrics:v1.2.0": "EXCEPTION Patch will applied this weekend"},
				{"ALL:dev": "Still working on it"},
			},
			ReflectIAMFindings: []map[string]string{
				{"arn:aws:iam::111111111111:role/eks-worker-dig-green-dev": "**EXCEPTION:** Ignore AccessDenied error. This role doesn't require s3.amazonaws.com/HeadObject access for its functionality"},
				{"arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass@someuser@company.com": "**EXCEPTION** this role is used by Jenkins and used as a service principal/account"},
			},
		},
	}

	cases := []struct {
		findingAccount   string
		findingType      string
		findingName      string
		expectedComments string
	}{
		{
			findingAccount:   "TEST_ACCOUNT1",
			findingType:      findingTypeTrustedAdvisor,
			findingName:      "SECURITY-IAM_Use",
			expectedComments: "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM",
		},
		{
			findingAccount:   "TEST_ACCOUNT1",
			findingType:      findingTypeAWSConfig,
			findingName:      "ATTACHED_INTERNET_GATEWAY_CHECK",
			expectedComments: "**EXCEPTION:** Flags VPCs that have an Internet Gateway attached, Most of our VPC requires IGW enabled in Public subnets as they are web application open to Internet. Better RULE would be to check VPC with all of its SUBNET open to IGW",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeAWSConfig,
			findingName:      "IAM_POLICY_BLACKLISTED_CHECK",
			expectedComments: "**EXCEPTION:** Removed the AdminstratorAccess policy since the default AWS_*_Admins uses the policy. Future enhancement would be to create a Custom Rule that no other Role can use the AdmnistratorAccess policy besides the AWS_*_Admins",
		},
		{
			findingAccount:   "TEST_ACCOUNT5",
			findingType:      findingTypeTrustedAdvisor,
			findingName:      "FAULT_TOLERANCE-Amazon_EBS_Snapshots",
			expectedComments: "NEW_FINDING",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeTrustedAdvisor,
			findingName:      "FAULT_TOLERANCE-S3_SSL",
			expectedComments: "NEW_FINDING",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeInspector,
			findingName:      "CIS_Operating_System_Security_Configuration_Benchmarks-1.0",
			expectedComments: "**EXCEPTION:** Description here",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeAWSHealth,
			findingName:      "AWS_RDS_SECURITY_NOTIFICATION",
			expectedComments: "NEW_FINDING",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeReflectIAM,
			findingName:      "arn:aws:iam::111111111111:role/eks-worker-dig-green-dev",
			expectedComments: "**EXCEPTION:** Ignore AccessDenied error. This role doesn't require s3.amazonaws.com/HeadObject access for its functionality",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeECRScan,
			findingName:      "333333333333.dkr.ecr.us-east-1.amazonaws.com/admin/kube-state-metrics:v1.2.0",
			expectedComments: "EXCEPTION Patch will applied this weekend",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeECRScan,
			findingName:      "333333333333.dkr.ecr.us-east-1.amazonaws.com/admin/sample:dev",
			expectedComments: "Still working on it",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeECRScan,
			findingName:      "333333333333.dkr.ecr.us-east-1.amazonaws.com/admin/sample:prod",
			expectedComments: "NEW_FINDING",
		},
		{
			findingAccount:   "TEST_ACCOUNT2",
			findingType:      findingTypeReflectIAM,
			findingName:      "arn:aws:iam::111111111111:role/do-it-all-role",
			expectedComments: "NEW_FINDING",
		},
	}

	for _, c := range cases {
		actualComments := getComments(comments, c.findingAccount, c.findingType, c.findingName)
		if diff := deep.Equal(c.expectedComments, actualComments); diff != nil {
			t.Fatalf("Expected comments are not correct, the difference is %s", diff)
		}
	}

}

func TestParseRoleARNs(t *testing.T) {
	testCases := []struct {
		name           string
		roleARNs       string
		expectedOutput []string
	}{
		{
			name:           "emptyStringPassed#1",
			roleARNs:       "",
			expectedOutput: []string{"parent"},
		},
		{
			name:           "roleARNsPassed#2",
			roleARNs:       "arn:aws:iam::123456:role/cloudig,arn:aws:iam::78910:role/cloudig",
			expectedOutput: []string{"arn:aws:iam::123456:role/cloudig", "arn:aws:iam::78910:role/cloudig"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := parseRoleARNs(tc.roleARNs)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestParseCommentsFile(t *testing.T) {
	testCases := []struct {
		name           string
		file           string
		expectedOutput []Comments
	}{
		{
			name: "returnExpectedCommentsArray#1",
			file: "../../test/data/comments.yaml",
			expectedOutput: []Comments{
				{
					AccountID:               "111111111111",
					TAFindings:              []map[string]string{{"SECURITY-IAM_Use": "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM"}},
					ConfigFindings:          []map[string]string{{"IAM_POLICY_BLACKLISTED_CHECK": "**EXCEPTION:** Removed the AdminstratorAccess policy since the default AWS_*_Admins uses the policy. Future enhancement would be to create a Custom Rule that no other Role can use the AdmnistratorAccess policy besides the AWS_*_Admins"}},
					InspectorReportFindings: []map[string]string{{"CIS_Operating_System_Security_Configuration_Benchmarks-1.0": "**EXCEPTION:** Description here"}},
					HealthReportFindings:    []map[string]string{{"AWS_RDS_SECURITY_NOTIFICATION": "**EXCEPTION:** Description here"}},
					ReflectIAMFindings:      []map[string]string{{"arn:aws:iam::111111111111:role/eks-worker-dig-green-dev": "**EXCEPTION:** Ignore AccessDenied error. This role doesn't require s3.amazonaws.com/HeadObject access for its functionality"}},
				},
				{
					AccountID: "222222222222",
					TAFindings: []map[string]string{
						{"SECURITY-IAM_Use": "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM"},
						{"FAULT_TOLERANCE-Amazon_EBS_Snapshots": "**EXCEPTION:** We do not persist any critical data on EC2 attached EBS. Data present in these disks are ephemeral in nature"},
					},
					ConfigFindings: []map[string]string{
						{"ATTACHED_INTERNET_GATEWAY_CHECK": "**EXCEPTION:** Flags VPCs that have an Internet Gateway attached, Most of our VPC requires IGW enabled in Public subnets as they are web application open to Internet. Better RULE would be to check VPC with all of its SUBNET open to IGW"},
						{"IAM_POLICY_BLACKLISTED_CHECK": "**EXCEPTION:** Removed the AdminstratorAccess policy since the default AWS_*_Admins uses the policy. Future enhancement would be to create a Custom Rule that no other Role can use the AdmnistratorAccess policy besides the AWS_*_Admins"},
					},
				},
				{
					AccountID: "012345678910",
					ImageScanFindings: []map[string]string{
						{"012345678910.dkr.ecr.us-east-1.amazonaws.com/app/web-server:prod-canary": "EXCEPTION Patch will applied this weekend"},
						{"ALL:v1.2.0": "EXCEPTION Patch is coming tomorrow"},
					},
				},
			},
		},
		{
			name:           "returnEmptyCommentsArrayWhenCommentsFileCan'tBeParsed#2",
			file:           "../../test/data/inspector_report_test.html",
			expectedOutput: []Comments(nil),
		},
		{
			name:           "returnEmptyCommentsArrayWhenCommentsFileDoesn'tExist#3",
			file:           "",
			expectedOutput: []Comments(nil),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := parseCommentsFile(tc.file)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}
