package cloudig

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/support"
	"github.com/stretchr/testify/assert"
)

func TestTrustedAdvisorTableOutput(t *testing.T) {
	testCases := []struct {
		name           string
		report         *TrustedAdvisorReport
		tableType      string
		expectedOutput string
	}{
		{
			name: "returnPopulatedTable#1",
			report: &TrustedAdvisorReport{
				Findings: []trustedAdvisorFinding{
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
						FlaggedResources: []string{"i-0123456789abcdefg", "i-abcdefg0123456789"},
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
			tableType: tableTypeNormal,
			expectedOutput: `+--------------+--------------------------------+---------------------+--------------------------------+
|  ACCOUNT ID  |              NAME              |  FLAGGED RESOURCES  |            COMMENTS            |
+--------------+--------------------------------+---------------------+--------------------------------+
| 111111111111 | COST_OPTIMIZING Low            | Flagged Count: 2    | NEW_FINDING                    |
|              | Utilization Amazon EC2         | i-0123456789abcdefg |                                |
|              | Instances                      | i-abcdefg0123456789 |                                |
+--------------+--------------------------------+---------------------+--------------------------------+
| 111111111111 | SECURITY                       | Flagged Count: 1    | **EXCEPTION:** We use          |
|              | IAM Use                        | NA                  | Federation and IAM roles to    |
|              |                                |                     | manage resources in AWS . No   |
|              |                                |                     | users/groups created in IAM    |
+--------------+--------------------------------+---------------------+--------------------------------+
`,
		},
		{
			name:      "returnEmptyTable#2",
			report:    &TrustedAdvisorReport{},
			tableType: tableTypeNormal,
			expectedOutput: `+------------+------+-------------------+----------+
| ACCOUNT ID | NAME | FLAGGED RESOURCES | COMMENTS |
+------------+------+-------------------+----------+
`,
		},
		{
			name: "returnPopulatedMDTable#3",
			report: &TrustedAdvisorReport{
				Findings: []trustedAdvisorFinding{
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
						FlaggedResources: []string{"i-0123456789abcdefg", "i-abcdefg0123456789"},
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
			tableType: tableTypeMD,
			expectedOutput: `|  ACCOUNT ID  |              NAME              |  FLAGGED RESOURCES  |            COMMENTS            |
|--------------|--------------------------------|---------------------|--------------------------------|
| 111111111111 | COST_OPTIMIZING Low            | Flagged Count: 2    | NEW_FINDING                    |
|              | Utilization Amazon EC2         | i-0123456789abcdefg |                                |
|              | Instances                      | i-abcdefg0123456789 |                                |
| 111111111111 | SECURITY                       | Flagged Count: 1    | **EXCEPTION:** We use          |
|              | IAM Use                        | NA                  | Federation and IAM roles to    |
|              |                                |                     | manage resources in AWS . No   |
|              |                                |                     | users/groups created in IAM    |
`,
		},
		{
			name:      "returnEmptyMDTable#4",
			report:    &TrustedAdvisorReport{},
			tableType: tableTypeMD,
			expectedOutput: `| ACCOUNT ID | NAME | FLAGGED RESOURCES | COMMENTS |
|------------|------|-------------------|----------|
`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := tc.report.toTable(tc.tableType)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestAWSConfigTableOutput(t *testing.T) {
	testCases := []struct {
		name           string
		report         *ConfigReport
		tableType      string
		expectedOutput string
	}{
		{
			name: "returnPopulatedTable#1",
			report: &ConfigReport{
				Findings: []configFinding{
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
			},
			tableType: tableTypeNormal,
			expectedOutput: `+--------------+---------------------------------------------+-------------------------------------+-------------+
|  ACCOUNT ID  |                    NAME                     |          FLAGGED RESOURCES          |  COMMENTS   |
+--------------+---------------------------------------------+-------------------------------------+-------------+
| 111111111111 | ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK | Resource Type:                      | NEW_FINDING |
|              |                                             | AWS::EC2::SecurityGroup             |             |
|              |                                             | sg-00003                            |             |
+--------------+---------------------------------------------+-------------------------------------+-------------+
| 111111111111 | S3_BUCKET_LOGGING_ENABLED                   | Resource Type: AWS::S3::Bucket      | NEW_FINDING |
|              |                                             | dig-log-bucket-nonprod-222222222222 |             |
+--------------+---------------------------------------------+-------------------------------------+-------------+
`,
		},
		{
			name:      "returnEmptyRable#2",
			report:    &ConfigReport{},
			tableType: tableTypeNormal,
			expectedOutput: `+------------+------+-------------------+----------+
| ACCOUNT ID | NAME | FLAGGED RESOURCES | COMMENTS |
+------------+------+-------------------+----------+
`,
		},
		{
			name: "returnPopulatedMDTable#3",
			report: &ConfigReport{
				Findings: []configFinding{
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
			},
			tableType: tableTypeMD,
			expectedOutput: `|  ACCOUNT ID  |                    NAME                     |          FLAGGED RESOURCES          |  COMMENTS   |
|--------------|---------------------------------------------|-------------------------------------|-------------|
| 111111111111 | ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK | Resource Type:                      | NEW_FINDING |
|              |                                             | AWS::EC2::SecurityGroup             |             |
|              |                                             | sg-00003                            |             |
| 111111111111 | S3_BUCKET_LOGGING_ENABLED                   | Resource Type: AWS::S3::Bucket      | NEW_FINDING |
|              |                                             | dig-log-bucket-nonprod-222222222222 |             |
`,
		},
		{
			name:      "returnEmptyMDTable#4",
			report:    &ConfigReport{},
			tableType: tableTypeMD,
			expectedOutput: `| ACCOUNT ID | NAME | FLAGGED RESOURCES | COMMENTS |
|------------|------|-------------------|----------|
`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := tc.report.toTable(tc.tableType)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestInspectorTableOutput(t *testing.T) {
	testCases := []struct {
		name            string
		reports         *InspectorReports
		tableType       string
		expectedOutput  string
		expectedOutput2 string
	}{
		{
			name: "returnPopulatedTables#1",
			reports: &InspectorReports{
				Reports: []inspectorReport{
					{
						AccountID:    "111111111111",
						TemplateName: "k8s_weekly_scan",
						Findings: []inspectorReportFinding{
							{
								RulePackageName: "CIS Operating System Security Configuration Benchmarks-1.0",
								High:            "2581",
								Medium:          "0",
								Low:             "0",
								Informational:   "232",
								Comments:        "**EXCEPTION:** Description here",
							},
							{
								RulePackageName: "Common Vulnerabilities and Exposures-1.1",
								High:            "29",
								Medium:          "46",
								Low:             "0",
								Informational:   "0",
								Comments:        "NEW_FINDING",
							},
							{
								RulePackageName: "Runtime Behavior Analysis-1.0",
								High:            "0",
								Medium:          "0",
								Low:             "23",
								Informational:   "44",
								Comments:        "NEW_FINDING",
							},
							{
								RulePackageName: "Security Best Practices-1.0",
								High:            "0",
								Medium:          "0",
								Low:             "0",
								Informational:   "0",
								Comments:        "NEW_FINDING",
							},
						},
						AMI: map[string]int{
							"TEST_AMI":   65,
							"TEST_AMI_2": 30,
						},
					},
				},
			},
			tableType: tableTypeNormal,
			expectedOutput: `+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
|  ACCOUNT ID  |  TEMPLATE NAME  |         RULE PACKAGES          | HIGH | MEDIUM | LOW | INFORMATIONAL |            COMMENTS            |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
| 111111111111 | k8s_weekly_scan | CIS Operating System Security  | 2581 |      0 |   0 |           232 | **EXCEPTION:** Description     |
|              |                 | Configuration Benchmarks-1.0   |      |        |     |               | here                           |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
| 111111111111 | k8s_weekly_scan | Common Vulnerabilities and     |   29 |     46 |   0 |             0 | NEW_FINDING                    |
|              |                 | Exposures-1.1                  |      |        |     |               |                                |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
| 111111111111 | k8s_weekly_scan | Runtime Behavior Analysis-1.0  |    0 |      0 |  23 |            44 | NEW_FINDING                    |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
| 111111111111 | k8s_weekly_scan | Security Best Practices-1.0    |    0 |      0 |   0 |             0 | NEW_FINDING                    |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
+--------------+------------+---------+
|  ACCOUNT ID  |    AMI     |   AGE   |
+--------------+------------+---------+
| 111111111111 | TEST_AMI   | 65 days |
+              +------------+---------+
|              | TEST_AMI_2 | 30 days |
+--------------+------------+---------+
`,
			expectedOutput2: `+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
|  ACCOUNT ID  |  TEMPLATE NAME  |         RULE PACKAGES          | HIGH | MEDIUM | LOW | INFORMATIONAL |            COMMENTS            |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
| 111111111111 | k8s_weekly_scan | CIS Operating System Security  | 2581 |      0 |   0 |           232 | **EXCEPTION:** Description     |
|              |                 | Configuration Benchmarks-1.0   |      |        |     |               | here                           |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
| 111111111111 | k8s_weekly_scan | Common Vulnerabilities and     |   29 |     46 |   0 |             0 | NEW_FINDING                    |
|              |                 | Exposures-1.1                  |      |        |     |               |                                |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
| 111111111111 | k8s_weekly_scan | Runtime Behavior Analysis-1.0  |    0 |      0 |  23 |            44 | NEW_FINDING                    |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
| 111111111111 | k8s_weekly_scan | Security Best Practices-1.0    |    0 |      0 |   0 |             0 | NEW_FINDING                    |
+--------------+-----------------+--------------------------------+------+--------+-----+---------------+--------------------------------+
+--------------+------------+---------+
|  ACCOUNT ID  |    AMI     |   AGE   |
+--------------+------------+---------+
| 111111111111 | TEST_AMI_2 | 30 days |
+              +------------+---------+
|              | TEST_AMI   | 65 days |
+--------------+------------+---------+
`,
		},
		{
			name:      "returnEmptyTables#2",
			reports:   &InspectorReports{},
			tableType: tableTypeNormal,
			expectedOutput: `+------------+---------------+---------------+------+--------+-----+---------------+----------+
| ACCOUNT ID | TEMPLATE NAME | RULE PACKAGES | HIGH | MEDIUM | LOW | INFORMATIONAL | COMMENTS |
+------------+---------------+---------------+------+--------+-----+---------------+----------+
+------------+-----+-----+
| ACCOUNT ID | AMI | AGE |
+------------+-----+-----+
+------------+-----+-----+
`,
		},
		{
			name: "returnPopulatedMDTables#3",
			reports: &InspectorReports{
				Reports: []inspectorReport{
					{
						AccountID:    "111111111111",
						TemplateName: "k8s_weekly_scan",
						Findings: []inspectorReportFinding{
							{
								RulePackageName: "CIS Operating System Security Configuration Benchmarks-1.0",
								High:            "2581",
								Medium:          "0",
								Low:             "0",
								Informational:   "232",
								Comments:        "**EXCEPTION:** Description here",
							},
							{
								RulePackageName: "Common Vulnerabilities and Exposures-1.1",
								High:            "29",
								Medium:          "46",
								Low:             "0",
								Informational:   "0",
								Comments:        "NEW_FINDING",
							},
							{
								RulePackageName: "Runtime Behavior Analysis-1.0",
								High:            "0",
								Medium:          "0",
								Low:             "23",
								Informational:   "44",
								Comments:        "NEW_FINDING",
							},
							{
								RulePackageName: "Security Best Practices-1.0",
								High:            "0",
								Medium:          "0",
								Low:             "0",
								Informational:   "0",
								Comments:        "NEW_FINDING",
							},
						},
						AMI: map[string]int{
							"TEST_AMI": 65,
						},
					},
					{
						AccountID:    "111111111111",
						TemplateName: "test_scan",
						Findings: []inspectorReportFinding{
							{
								RulePackageName: "CIS Operating System Security Configuration Benchmarks-1.0",
								High:            "123",
								Medium:          "0",
								Low:             "0",
								Informational:   "232",
								Comments:        "**EXCEPTION:** Description here",
							},
							{
								RulePackageName: "Common Vulnerabilities and Exposures-1.1",
								High:            "7",
								Medium:          "50",
								Low:             "0",
								Informational:   "0",
								Comments:        "NEW_FINDING",
							},
							{
								RulePackageName: "Runtime Behavior Analysis-1.0",
								High:            "0",
								Medium:          "0",
								Low:             "60",
								Informational:   "45",
								Comments:        "NEW_FINDING",
							},
							{
								RulePackageName: "Security Best Practices-1.0",
								High:            "0",
								Medium:          "0",
								Low:             "0",
								Informational:   "0",
								Comments:        "NEW_FINDING",
							},
						},
						AMI: map[string]int{
							"TEST_AMI": 65,
						},
					},
				},
			},
			tableType: tableTypeMD,
			expectedOutput: `|  ACCOUNT ID  |  TEMPLATE NAME  |         RULE PACKAGES          | HIGH | MEDIUM | LOW | INFORMATIONAL |            COMMENTS            |
|--------------|-----------------|--------------------------------|------|--------|-----|---------------|--------------------------------|
| 111111111111 | k8s_weekly_scan | CIS Operating System Security  | 2581 |      0 |   0 |           232 | **EXCEPTION:** Description     |
|              |                 | Configuration Benchmarks-1.0   |      |        |     |               | here                           |
| 111111111111 | k8s_weekly_scan | Common Vulnerabilities and     |   29 |     46 |   0 |             0 | NEW_FINDING                    |
|              |                 | Exposures-1.1                  |      |        |     |               |                                |
| 111111111111 | k8s_weekly_scan | Runtime Behavior Analysis-1.0  |    0 |      0 |  23 |            44 | NEW_FINDING                    |
| 111111111111 | k8s_weekly_scan | Security Best Practices-1.0    |    0 |      0 |   0 |             0 | NEW_FINDING                    |
| 111111111111 | test_scan       | CIS Operating System Security  |  123 |      0 |   0 |           232 | **EXCEPTION:** Description     |
|              |                 | Configuration Benchmarks-1.0   |      |        |     |               | here                           |
| 111111111111 | test_scan       | Common Vulnerabilities and     |    7 |     50 |   0 |             0 | NEW_FINDING                    |
|              |                 | Exposures-1.1                  |      |        |     |               |                                |
| 111111111111 | test_scan       | Runtime Behavior Analysis-1.0  |    0 |      0 |  60 |            45 | NEW_FINDING                    |
| 111111111111 | test_scan       | Security Best Practices-1.0    |    0 |      0 |   0 |             0 | NEW_FINDING                    |
|  ACCOUNT ID  |   AMI    |   AGE   |
|--------------|----------|---------|
| 111111111111 | TEST_AMI | 65 days |
|              |          |         |
`,
		},
		{
			name:      "returnEmptyMDTables#4",
			reports:   &InspectorReports{},
			tableType: tableTypeMD,
			expectedOutput: `| ACCOUNT ID | TEMPLATE NAME | RULE PACKAGES | HIGH | MEDIUM | LOW | INFORMATIONAL | COMMENTS |
|------------|---------------|---------------|------|--------|-----|---------------|----------|
| ACCOUNT ID | AMI | AGE |
|------------|-----|-----|
`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := tc.reports.toTable(tc.tableType)
			assert.Contains(t, []string{tc.expectedOutput, tc.expectedOutput2}, output)
		})
	}
}

func TestHealthTableOutput(t *testing.T) {
	testCases := []struct {
		name           string
		report         *HealthReport
		tableType      string
		expectedOutput string
	}{
		{
			name: "returnPopulatedTable#1",
			report: &HealthReport{
				Findings: []healthReportFinding{
					{
						AccountID:        "111111111111",
						AffectedEntities: []string{"the-entity-0"},
						Arn:              "arn1",
						Comments:         "**EXCEPTION:** Description",
						EventTypeCode:    "Rds Security Notification",
						LastUpdatedTime:  "0001-01-01 00:00:00 +0000 UTC",
						Region:           "us-east-2",
						StatusCode:       "open",
						EventDescription: "description",
					},
					{
						AccountID: "111111111111",
						AffectedEntities: []string{
							"a-entity-0",
							"a-entity-1",
							"a-entity-3",
							"a-entity-4",
						},
						Arn:              "arn1",
						Comments:         "**EXCEPTION:** Description",
						EventTypeCode:    "Rds Security Notification",
						LastUpdatedTime:  "0001-01-01 00:00:00 +0000 UTC",
						Region:           "us-east-2",
						StatusCode:       "open",
						EventDescription: "description",
					},
					{
						AccountID: "111111111111",
						AffectedEntities: []string{
							"some-entity-0",
							"some-entity-1",
						},
						Arn:              "arn1",
						Comments:         "NEW_FINDING",
						EventTypeCode:    "Rds Operational Notification",
						LastUpdatedTime:  "0001-01-01 00:00:00 +0000 UTC",
						Region:           "us-east-2",
						StatusCode:       "open",
						EventDescription: "description",
					},
				},
			},
			tableType: tableTypeNormal,
			expectedOutput: `+--------------+------------------------------+-----------+-------------+-------------------+--------------------------------+----------------------------+
|  ACCOUNT ID  |       EVENT TYPE CODE        |  REGION   | STATUS CODE | EVENT DESCRIPTION |       AFFECTED RESOURCES       |          COMMENTS          |
+--------------+------------------------------+-----------+-------------+-------------------+--------------------------------+----------------------------+
| 111111111111 | Rds Security Notification    | us-east-2 | open        | description       | the-entity-0                   | **EXCEPTION:** Description |
+--------------+------------------------------+-----------+-------------+-------------------+--------------------------------+----------------------------+
| 111111111111 | Rds Security Notification    | us-east-2 | open        | description       | a-entity-0, a-entity-1,        | **EXCEPTION:** Description |
|              |                              |           |             |                   | a-entity-3, a-entity-4         |                            |
+--------------+------------------------------+-----------+-------------+-------------------+--------------------------------+----------------------------+
| 111111111111 | Rds Operational Notification | us-east-2 | open        | description       | some-entity-0, some-entity-1   | NEW_FINDING                |
+--------------+------------------------------+-----------+-------------+-------------------+--------------------------------+----------------------------+
`,
		},
		{
			name:      "returnEmptyTable#2",
			report:    &HealthReport{},
			tableType: tableTypeNormal,
			expectedOutput: `+------------+-----------------+--------+-------------+-------------------+--------------------+----------+
| ACCOUNT ID | EVENT TYPE CODE | REGION | STATUS CODE | EVENT DESCRIPTION | AFFECTED RESOURCES | COMMENTS |
+------------+-----------------+--------+-------------+-------------------+--------------------+----------+
`,
		},
		{
			name: "returnPopulatedMDTable#3",
			report: &HealthReport{
				Findings: []healthReportFinding{
					{
						AccountID:        "111111111111",
						AffectedEntities: []string{"the-entity-0"},
						Arn:              "arn1",
						Comments:         "**EXCEPTION:** Description",
						EventTypeCode:    "Rds Security Notification",
						LastUpdatedTime:  "0001-01-01 00:00:00 +0000 UTC",
						Region:           "us-east-2",
						StatusCode:       "open",
						EventDescription: "description",
					},
					{
						AccountID: "111111111111",
						AffectedEntities: []string{
							"a-entity-0",
							"a-entity-1",
							"a-entity-3",
							"a-entity-4",
						},
						Arn:              "arn1",
						Comments:         "**EXCEPTION:** Description",
						EventTypeCode:    "Rds Security Notification",
						LastUpdatedTime:  "0001-01-01 00:00:00 +0000 UTC",
						Region:           "us-east-2",
						StatusCode:       "open",
						EventDescription: "description",
					},
					{
						AccountID: "111111111111",
						AffectedEntities: []string{
							"some-entity-0",
							"some-entity-1",
						},
						Arn:              "arn1",
						Comments:         "NEW_FINDING",
						EventTypeCode:    "Rds Operational Notification",
						LastUpdatedTime:  "0001-01-01 00:00:00 +0000 UTC",
						Region:           "us-east-2",
						StatusCode:       "open",
						EventDescription: "description",
					},
				},
			},
			tableType: tableTypeMD,
			expectedOutput: `|  ACCOUNT ID  |       EVENT TYPE CODE        |  REGION   | STATUS CODE | EVENT DESCRIPTION |       AFFECTED RESOURCES       |          COMMENTS          |
|--------------|------------------------------|-----------|-------------|-------------------|--------------------------------|----------------------------|
| 111111111111 | Rds Security Notification    | us-east-2 | open        | description       | the-entity-0                   | **EXCEPTION:** Description |
| 111111111111 | Rds Security Notification    | us-east-2 | open        | description       | a-entity-0, a-entity-1,        | **EXCEPTION:** Description |
|              |                              |           |             |                   | a-entity-3, a-entity-4         |                            |
| 111111111111 | Rds Operational Notification | us-east-2 | open        | description       | some-entity-0, some-entity-1   | NEW_FINDING                |
`,
		},
		{
			name:      "returnEmptyMDTable#4",
			report:    &HealthReport{},
			tableType: tableTypeMD,
			expectedOutput: `| ACCOUNT ID | EVENT TYPE CODE | REGION | STATUS CODE | EVENT DESCRIPTION | AFFECTED RESOURCES | COMMENTS |
|------------|-----------------|--------|-------------|-------------------|--------------------|----------|
`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := tc.report.toTable(tc.tableType)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestReflectReportTableOutput(t *testing.T) {
	testCases := []struct {
		name           string
		report         *ReflectReport
		tableType      string
		expectedOutput string
	}{
		{
			name: "returnPopulatedTable#1",
			report: &ReflectReport{
				Findings: []reflectFinding{
					{
						AccountID: "111111111111",
						Identity:  "arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass",
						AccessDetails: []accessDetails{
							{"sts.amazonaws.com/AssumeRole", 15},
							{"sts.amazonaws.com/AssumeRole/AccessDenied", 15},
						},
						PermissionSet: []string{"kms:ListKeys", "kms:ListGrants", "kms:GenerateDataKeyWithoutPlaintext"},
						Comments:      "**EXCEPTION:** I am too tired to write a test case",
					},
					{
						AccountID: "111111111111",
						Identity:  "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
						AccessDetails: []accessDetails{
							{"iam.amazonaws.com/UpdateAssumeRolePolicy", 1},
							{"iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied", 1},
						},
						PermissionSet: []string{"kms:Encrypt", "kms:DescribeKey"},
						Comments:      "NEW_FINDING",
					},
					{
						AccountID:     "111111111111",
						Identity:      "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
						AccessDetails: []accessDetails{},
						PermissionSet: []string{"kms:Encrypt", "kms:DescribeKey"},
						Comments:      "**EXCEPTION:** lets get this over with!",
					},
				},
			},
			tableType: tableTypeNormal,
			expectedOutput: `+--------------+------------------------------------------------------------+---------------------------------------------------------+-------------------------------------+--------------------------------+
|  ACCOUNT ID  |                        IAM IDENTITY                        |                     ACCESS DETAILS                      |         ACTUAL PERMISSIONS          |            COMMENTS            |
+--------------+------------------------------------------------------------+---------------------------------------------------------+-------------------------------------+--------------------------------+
| 111111111111 | arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass | sts.amazonaws.com/AssumeRole:15                         | kms:ListKeys kms:ListGrants         | **EXCEPTION:** I am too tired  |
|              |                                                            | sts.amazonaws.com/AssumeRole/AccessDenied:15            | kms:GenerateDataKeyWithoutPlaintext | to write a test case           |
+--------------+------------------------------------------------------------+---------------------------------------------------------+-------------------------------------+--------------------------------+
| 111111111111 | arn:aws:iam::111111111111:role/AWS_111111111111_Read       | iam.amazonaws.com/UpdateAssumeRolePolicy:1              | kms:Encrypt                         | NEW_FINDING                    |
|              |                                                            | iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied:1 | kms:DescribeKey                     |                                |
+--------------+------------------------------------------------------------+---------------------------------------------------------+-------------------------------------+--------------------------------+
| 111111111111 | arn:aws:iam::111111111111:role/AWS_111111111111_Read       |                                                         | kms:Encrypt                         | **EXCEPTION:** lets get this   |
|              |                                                            |                                                         | kms:DescribeKey                     | over with!                     |
+--------------+------------------------------------------------------------+---------------------------------------------------------+-------------------------------------+--------------------------------+
`,
		},
		{
			name: "returnPopulatedMDTable#2",
			report: &ReflectReport{
				Findings: []reflectFinding{
					{
						AccountID: "111111111111",
						Identity:  "arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass",
						AccessDetails: []accessDetails{
							{"sts.amazonaws.com/AssumeRole", 15},
							{"sts.amazonaws.com/AssumeRole/AccessDenied", 15},
						},
						PermissionSet: []string{"kms:ListKeys", "kms:ListGrants", "kms:GenerateDataKeyWithoutPlaintext"},
						Comments:      "**EXCEPTION:** I am too tired to write a test case",
					},
					{
						AccountID: "111111111111",
						Identity:  "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
						AccessDetails: []accessDetails{
							{"iam.amazonaws.com/UpdateAssumeRolePolicy", 1},
							{"iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied", 1},
						},
						PermissionSet: []string{"kms:Encrypt", "kms:DescribeKey"},
						Comments:      "NEW_FINDING",
					},
					{
						AccountID:     "111111111111",
						Identity:      "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
						AccessDetails: []accessDetails{},
						PermissionSet: []string{"kms:Encrypt", "kms:DescribeKey"},
						Comments:      "**EXCEPTION:** lets get this over with!",
					},
				},
			},
			tableType: tableTypeMD,
			expectedOutput: `|  ACCOUNT ID  |                        IAM IDENTITY                        |                     ACCESS DETAILS                      |         ACTUAL PERMISSIONS          |            COMMENTS            |
|--------------|------------------------------------------------------------|---------------------------------------------------------|-------------------------------------|--------------------------------|
| 111111111111 | arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass | sts.amazonaws.com/AssumeRole:15                         | kms:ListKeys kms:ListGrants         | **EXCEPTION:** I am too tired  |
|              |                                                            | sts.amazonaws.com/AssumeRole/AccessDenied:15            | kms:GenerateDataKeyWithoutPlaintext | to write a test case           |
| 111111111111 | arn:aws:iam::111111111111:role/AWS_111111111111_Read       | iam.amazonaws.com/UpdateAssumeRolePolicy:1              | kms:Encrypt                         | NEW_FINDING                    |
|              |                                                            | iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied:1 | kms:DescribeKey                     |                                |
| 111111111111 | arn:aws:iam::111111111111:role/AWS_111111111111_Read       |                                                         | kms:Encrypt                         | **EXCEPTION:** lets get this   |
|              |                                                            |                                                         | kms:DescribeKey                     | over with!                     |
`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := tc.report.toTable(tc.tableType)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}
