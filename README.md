[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/optum/cloudig/graphs/commit-activity)
![build](https://github.com/optum/cloudig/workflows/build/badge.svg?branch=main)
[![Github all releases](https://img.shields.io/github/downloads/optum/cloudig/total.svg)](https://GitHub.com/optum/cloudig/releases/)

[comment]: <> (<a href="https://cla-assistant.io/Optum/cloudig"><img src="https://cla-assistant.io/readme/badge/Optum/cloudig" alt="CLA assistant" /></a>)

[![made-with-Go](https://img.shields.io/badge/Made%20with-Go-1f425f.svg)](http://golang.org)

![cloudig](./logo.png)

cloudig, or Cloudigest, is a simple CLI tool for creating reports from various cloud sources with user-provided comments. It is written in Go and currently uses AWS APIs to generate reports based on five pillars — operational excellence, security, reliability, performance efficiency, and cost optimization. CLI allows users to provide comments for documenting exceptions and work in progress. This report can be useful in various use cases such as a quality gate step in IaC CI/CD pipeline, daily monitoring for operations to keep account status of multiple accounts in green status, single source for enterprise security/compliance teams to endorse the accounts, etc.

The currently supported cloud sources are:

- [AWS IAM Reflect](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html): This custom source uses [CloudTrail](https://aws.amazon.com/cloudtrail/) for event history of AWS IAM role activity and IAM to compare the actual permissions.

- [AWS Trusted Advisor](https://aws.amazon.com/premiumsupport/trustedadvisor/): Provides real time guidance to help provision resources following AWS best practices. 100+ checks on cost optimization, security, fault tolerance, performance, and service limits

- [AWS Config](https://aws.amazon.com/config/): Continuously monitors and records our AWS resource configurations and allows us to automate the evaluation of recorded configurations against desired configurations. This [module](https://github.com/Optum/aws_config) can help enable AWS Config with the desired configuration baseline.

- [AWS Inspector](https://aws.amazon.com/inspector/): Automatically assesses applications running in EC2 instances for exposure, vulnerabilities, and deviations from best practices. After performing an assessment, Amazon Inspector produces a detailed list of security findings prioritized by level of severity.

- [AWS ECR Scan](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html) : Provides image scanning to identify software vulnerabilities in container images.

- [AWS Health Notifications](https://aws.amazon.com/premiumsupport/technology/personal-health-dashboard/): Provides relevant and timely information to help manage events in progress, and provides proactive notification to help you plan for scheduled activities.

### Example output:

```
[ℹ]  reading comments from file comments.yaml
[ℹ]  working on reflect report for account: 111111111111
[ℹ]  getting the s3 prefix associated with the CloudTrail
[ℹ]  constructing the Athena table metadata form the s3 prefix
[ℹ]  finding the existing Athena table from the constructed metadata
[ℹ]  found the existing Athena table: default.reflect_cloudtrail_gxev4
[ℹ]  populating findings for roles
[✔]  successfully populated the findings for roles
[ℹ]  finding the actual permission for the roles
[✔]  reflecting on account 111111111111 took 23.793137533s
{
  "findings": [
    {
      "accountId": "111111111111",
      "IAMIdentity": "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
      "accessDetails": [
        {
          "IAMAction": "kms.amazonaws.com/Decrypt",
          "UsageCount": 3
        }
      ],
      "permissionSet": [
        "kms:ListKeys",
        "kms:ListGrants",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:GenerateDataKey",
        "kms:Encrypt",
        "kms:DescribeKey",
        "kms:Decrypt",
        "events:PutEvents"
      ],
      "comments": "**WORK_IN_PROGRESS:** Lot of unnecessary permissions"
    }
  ],
  "reportTime": "21 Dec 20 10:53 CST"
}
```

### Installation

`cloudig` can be installed two ways:

1. Downloading latest release binary:

```bash
# <ARCH> Darwin_arm64 
# <VERSION> 0.1.0

 curl -O https://github.com/Optum/cloudig/releases/download/v<VERSION>/cloudig_<VERSION>_<ARCH>.tar.gz  \
 &&  tar -xf cloudig_<VERSION>_<ARCH>.tar.gz \
 && chmod +x cloudig \
 && mv cloudig /usr/local/bin \
 && cloudig --help
```

2. Cloning repo and running `make build` **NOTE: must have Go installed**

```bash
git clone https://github.com/Optum/cloudig.git

cd cloudig

make build

./cloudig --help
```

#### CLI Verbs

`get` - Get reports. Get ready-made reports directly from sources like Trusted Advisor, ECR scan, etc.

`reflect` - Reflect on resources. Custom reports based on past usage and current configurations. Ex: Reflect on IAM role usage.

#### Global Flags

`--help`,`-h` : Generate help documentation

`--version` : Prints version of the CLI

`--rolearn`: (Optional) Takes the comma separated list of role ARN's. Provided role must have minimum permission needed to pull findings from AWS sources. Also, your parent account must have trust relationship so it can assume the role. When no role is provided, findings are only from the account associated with provided credentials

`--cfile`, `-c`: (Optional) YAML file to provide user comments for each finding. When this file is not provided, each finding is treated as a new finding

`--region`, `-r`: (Optional) AWS region to get results from. Default is us-east-1

`--output`, `-o`: (Optional) Output of the report. Options: json, table, and mdtable. Default is JSON

`--verbose`, `-v`: (Optional) set log level, use 0 to silence, 1 for critical, 2 for warning, 3 for informational, 4 for debugging and 5 for debugging with AWS debug logging (default 3)

#### IAM Reflect source specific flags

`--identity`, `-i`: (Optional) One or more IAM Identities (users, groups, and roles) ARNs separated by a comma [,]. Only role ARN is supported today

`--identity-tags`, `-t`: (Optional) Set of tags in form [key:value] separated by [,] to find the targeted IAM Identities. Only role ARNs is supported today. Ignored when --identity is provided

`--usage`, `-u` : (Optional) Reflect Identity usage data (default true, if --errors/-e is not explicitly provided)

`--errors`, `-e` : (Optional) Reflect Identity error data (default true, if --usage/-u is not explicitly provided)

`--caller-identity` : (Optional) Include caller identity with the report(default false)

`--absolute-time` : (Optional) Specify both the start and end times for the time filter in the form 'startTime-endTime' 'mm/dd/yyyy-mm/dd/yyy' ex: '10/25/2020-10/31/2020'

`--relative-time` : (Optional) Specify a time filter relative to the current time in days. Default 1 day. Ignored when absolute-time is provided

#### Health source specific flags

`--details`, `-d`: (Optional) Health event descriptions are often very long, thus, by default, it is shortened to three sentences. If this flag is added, then the entire description is printed out.

`--pastdays`: (Optional) Number of past days to get results from. Default is all health events that are open / upcoming.

#### Source specific examples:

- [IAM Reflect](doc/reflectiam.md)
- [TrustedAdvisor](doc/trustedadvisor.md)
- [AWS Config](doc/awsconfig.md)
- [Inspector](doc/inspector.md)
- [ECR Scan](doc/ecrscan.md)
- [AWS Health](doc/health.md)

#### Disclaimer

Even though the goal of "IAM reflect" is following the "Principle of least privilege" by keeping "Configured Permissions" equal to "Actual used Permissions", it is not always possible. This is mainly because some of the API actions for various AWS services are not tracked in CloudTrail, such as S3 & CloudWatch data events.
Also, in some cases, API actions are named slightly differently. Don't let the perfect be the enemy of the good. Use this wisely!
More info [1](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html#cloudtrail-aws-service-specific-topics-list) & [2](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-and-data-events-with-cloudtrail.html#logging-data-events)

Reflect uses CloudTrail event data stored in S3 and currently assumes partitions in the form `${Trail log location}/${region}/${year}/${month}/${day}`.
It returns zero results if it doesn't find the necessary partitions. We should be able to support different partition schemes in future releases.

#### Comment file(cfile):

Comment file provides a way to pass in user comments to findings from various sources. By default, CLI looks for the file name 'comments.yaml' to parse the comments.
User can also provide a different location by using flag `--cfile` or `-c`

Below is the sample file:

```yaml
- accountid: "111111111111"
  ta-findings:
    - SECURITY-IAM_Use: "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM"
  config-findings:
    - IAM_POLICY_BLACKLISTED_CHECK: "**EXCEPTION:** Removed the AdministratorAccess policy since the default AWS_*_Admins uses the policy. Future enhancement would be to create a Custom Rule that no other Role can use the AdministratorAccess policy besides the AWS_*_Admins"
  inspector-findings:
    - CIS_Operating_System_Security_Configuration_Benchmarks-1.0: "**EXCEPTION:*** Description here"
  health-findings:
    - AWS_RDS_SECURITY_NOTIFICATION: "**EXCEPTION:** Description here"
```

#### IAM permission requirements

Sample Policy needed to run cloudig and ability to use assume role to run report across multiple accounts:

```hcl
data "aws_iam_policy_document" "cloudig_policy" {
  statement {
    effect = "Allow"

    actions = [
      "support:*",
      "config:GetComplianceSummaryByConfigRule",
      "config:GetComplianceDetailsByConfigRule",
      "config:DescribeComplianceByConfigRule",
      "config:DescribeComplianceByResource",
      "config:DescribeConfigRules",
      "health:DescribeEvents",
      "health:DescribeEventDetails",
      "health:DescribeAffectedEntities",
      "inspector:GetAssessmentReport",
      "inspector:ListAssessmentRuns",
      "inspector:ListAssessmentTemplates",
      "inspector:DescribeAssessmentTemplates",
      "inspector:DescribeAssessmentTargets",
      "inspector:DescribeResourceGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:DescribeImages",
      "ecr:DescribeImageScanFindings",
      "iam:ListRolePolicies",
      "iam:ListRoles",
      "iam:ListRoleTags",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:GetPolicyVersion",
      "sts:GetCallerIdentity",
      "s3:ListBucket",
      "s3:GetObject",
      "s3:PutObject",
      "s3:GetBucketLocation",
      "cloudtrail:DescribeTrails",
      "athena:GetQueryExecution",
      "athena:StartQueryExecution",
      "athena:ListTableMetadata",
      "athena:ListDatabases",
      "athena:GetTableMetadata",
      "athena:ListDataCatalogs",
      "athena:GetQueryResults",
      "glue:GetTables",
      "glue:GetDatabase",
      "glue:CreateTable",
      "glue:GetDatabases",
      "glue:GetTable",
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "cloudig_assume_role" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111111111111:role/AWS_111111111111_Read"]
    }
  }
}

resource "aws_iam_role" "cloudig_role" {
  name               = "cloudig"
  assume_role_policy = data.aws_iam_policy_document.cloudig_assume_role.json
}

resource "aws_iam_role_policy" "cloudig_policy" {
  name   = "cloudig"
  role   = aws_iam_role.cloudig_role.id
  policy = data.aws_iam_policy_document.cloudig_policy.json
}
```

**Note**: Support doesn't let you allow or deny access to individual actions. Therefore, the Action element of a policy is always set to support:_.
Similarly, Support & Inspector don't provide resource-level access, so the Resource element is always set to _. Need access to EC2 for getting AMI information

### Developer Notes

#### Build

cloudig uses the Go Modules support built into Go 1.11. Make sure installed go version is at least 1.11

`go build -o cloudig` OR `make build`

Build for different Target OS and Platform:

`env GOOS=<target-OS> GOARCH=<target-architecture> go build -o cloudig`

OR

`make compile`

- This will compile the 64-bit binaries for Linux, Windows, and Mac

#### Testing

Running the tests: `make test`

Validating the test coverage :

```bash
go test -v -coverprofile cover.out github.com/Optum/cloudig/pkg/cloudig

go tool cover -html=cover.out // opens a html output in default browser

```

**Testing methodology**:

cloudig tests are written using the [GoMock](https://github.com/golang/mock) mocking framework and table-driven tests.

A few of the reasons we chose to use GoMock are:

1. Allows us to write tests for functions that make API calls without actually making the call.

2. Integrates well with the standard library testing package: `testing`.

Examples of these tests can be found under the `pkg/aws` and `pkg/cloudig` folders

The mocks that were generated can be found under the `pkg/mocks` folder and the commands used to generate them can be found [here](/pkg/mocks/README.md)

#### Logging

This project uses a very simple but effective [logger library](https://github.com/kris-nova/logger) that allows us to set a different logging level with the flag `--verbose` or `-v`. Different levels are 1 for critical, 2 for warning, 3 for informational, 4 for debugging, and 5 for debugging with AWS debug logging with the default being 3 (informational).

- Files supporting commands in `package cmd` and controller logic in `package cloudig` are instrumented to log at a different level.
- AWS interactions in `package aws` are purposefully kept out of adding more logging as we can always use `-v5` to enable AWS SDK debug logging. All methods in AWS client is expected to promptly propagate the error back to the caller to avoid duplicate logging.
