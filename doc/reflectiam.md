Reflect: `cloudig reflect iam`

Examples:

- Reflect on single IAM role based on last 4 days of CloudTrail data:

  `cloudig reflect iam -i arn:aws:iam::111111111111:role/web-gateway-greencherry-dev --relative-time 4`

- Reflect on multiple IAM roles between specific dates:

  `cloudig reflect iam -i 'arn:aws:iam::111111111111:role/web-gateway-greencherry-dev,arn:aws:iam::111111111111:role/admin-gateway-greencherry-dev' --absolute-time '11/20/2020-12/04/2020' -o table`

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
  [✔]  reflecting on account 111111111111 took 44.725057955s
  [✿]  report Time: 21 Dec 20 12:47 CST
  +--------------+--------------------------------------------------------------+------------------------------+-------------------------------------+--------------------------------+
  |  ACCOUNT ID  |                         IAM IDENTITY                         |        ACCESS DETAILS        |         ACTUAL PERMISSIONS          |            COMMENTS            |
  +--------------+--------------------------------------------------------------+------------------------------+-------------------------------------+--------------------------------+
  | 111111111111 | arn:aws:iam::111111111111:role/admin-gateway-greencherry-dev | kms.amazonaws.com/Decrypt:2  | kms:ListKeys kms:ListGrants         | NEW_FINDING                    |
  |              |                                                              |                              | kms:GenerateDataKeyWithoutPlaintext |                                |
  |              |                                                              |                              | kms:GenerateDataKey kms:Encrypt     |                                |
  |              |                                                              |                              | kms:DescribeKey kms:Decrypt         |                                |
  |              |                                                              |                              | events:PutEvents                    |                                |
  +--------------+--------------------------------------------------------------+------------------------------+-------------------------------------+--------------------------------+
  | 111111111111 | arn:aws:iam::111111111111:role/web-gateway-greencherry-dev   | kms.amazonaws.com/Decrypt:10 | kms:ListKeys kms:ListGrants         | **WORK_IN_PROGRESS:** Lot of   |
  |              |                                                              |                              | kms:GenerateDataKeyWithoutPlaintext | unnecessary permissions        |
  |              |                                                              |                              | kms:GenerateDataKey kms:Encrypt     |                                |
  |              |                                                              |                              | kms:DescribeKey kms:Decrypt         |                                |
  |              |                                                              |                              | events:PutEvents                    |                                |
  +--------------+--------------------------------------------------------------+------------------------------+-------------------------------------+--------------------------------+
  ```

* Reflect on usage of a specific role with caller identity:

  `cloudig reflect iam -i 'arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass' --caller-identity -o mdtable --relative-time 5`

```
|  ACCOUNT ID  |                                    IAM IDENTITY                                     |                         ACCESS DETAILS                         |       ACTUAL PERMISSIONS       |  COMMENTS   |
|--------------|-------------------------------------------------------------------------------------|----------------------------------------------------------------|--------------------------------|-------------|
| 111111111111 | arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass@someuser@company.com     | ecr.amazonaws.com/BatchCheckLayerAvailability:63               | The role with name             | NEW_FINDING |
|              |                                                                                     | sts.amazonaws.com/GetCallerIdentity:39                         | AWS_111111111111_BreakGlass    |             |
|              |                                                                                     | ecr.amazonaws.com/UploadLayerPart:33                           | cannot be found.               |             |
|              |                                                                                     | kms.amazonaws.com/Decrypt:28                                   |                                |             |
|              |                                                                                     | ecr.amazonaws.com/CompleteLayerUpload:23                       |                                |             |
|              |                                                                                     | ecr.amazonaws.com/InitiateLayerUpload:23                       |                                |             |
|              |                                                                                     | health.amazonaws.com/DescribeEventAggregates:13                |                                |             |
|              |                                                                                     | route53.amazonaws.com/GetHostedZone:2                          |                                |             |
|              |                                                                                     | route53.amazonaws.com/ListTagsForResource:2                    |                                |             |
|              |                                                                                     | cognito-sync.amazonaws.com/GetIdentityPoolConfiguration:2      |                                |             |
|              |                                                                                     | cognito-identity.amazonaws.com/DescribeIdentityPool:2          |                                |             |
|              |                                                                                     | ecr.amazonaws.com/GetAuthorizationToken:2                      |                                |             |
|              |                                                                                     | lambda.amazonaws.com/ListFunctions20150331:2                   |                                |             |
|              |                                                                                     | route53.amazonaws.com/GetHostedZoneCount:2                     |                                |             |
|              |                                                                                     | cognito-identity.amazonaws.com/GetIdentityPoolRoles:2          |                                |             |
|              |                                                                                     | cognito-identity.amazonaws.com/ListIdentityPools:2             |                                |             |
|              |                                                                                     | cognito-sync.amazonaws.com/DescribeIdentityPoolUsage:2         |                                |             |
|              |                                                                                     | ecr.amazonaws.com/PutImage:2                                   |                                |             |
|              |                                                                                     | route53.amazonaws.com/ListResourceRecordSets:2                 |                                |             |
|              |                                                                                     | iam.amazonaws.com/GetRole:2                                    |                                |             |
|              |                                                                                     | route53.amazonaws.com/ListQueryLoggingConfigs:2                |                                |             |
|              |                                                                                     | sns.amazonaws.com/ListPlatformApplications:1                   |                                |             |
|              |                                                                                     | route53domains.amazonaws.com/ListDomains:1                     |                                |             |
|              |                                                                                     | iam.amazonaws.com/ListRoles:1                                  |                                |             |
|              |                                                                                     | route53.amazonaws.com/ListTrafficPolicies:1                    |                                |             |
|              |                                                                                     | route53domains.amazonaws.com/ListOperations:1                  |                                |             |
|              |                                                                                     | iam.amazonaws.com/ListSAMLProviders:1                          |                                |             |
|              |                                                                                     | route53.amazonaws.com/ChangeResourceRecordSets:1               |                                |             |
|              |                                                                                     | kinesis.amazonaws.com/ListStreams:1                            |                                |             |
|              |                                                                                     | cognito-sync.amazonaws.com/GetBulkPublishDetails:1             |                                |             |
|              |                                                                                     | ec2.amazonaws.com/DescribeVpcs:1                               |                                |             |
|              |                                                                                     | iam.amazonaws.com/ListOpenIDConnectProviders:1                 |                                |             |
|              |                                                                                     | route53.amazonaws.com/GetHealthCheckCount:1                    |                                |             |
|              |                                                                                     | route53.amazonaws.com/ListHostedZonesByName:1                  |                                |             |
|              |                                                                                     | route53.amazonaws.com/GetTrafficPolicyInstanceCount:1          |                                |             |
|              |                                                                                     | cognito-sync.amazonaws.com/GetCognitoEvents:1                  |                                |             |
| 111111111111 | arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass@otheruser@company.com    | s3.amazonaws.com/ListObjects:5                                 | The role with name             | NEW_FINDING |
|              |                                                                                     | sts.amazonaws.com/GetCallerIdentity:4                          | AWS_111111111111_BreakGlass    |             |
|              |                                                                                     | s3.amazonaws.com/GetObject:4                                   | cannot be found.               |             |
|              |                                                                                     | s3.amazonaws.com/ListBuckets:1                                 |                                |             |
|              |                                                                                     | s3.amazonaws.com/PutObject:1                                   |                                |             |
```

- Reflect on set of roles based on tags:

  `cloudig reflect iam -t 'terraform:True' --caller-identity -o mdtable --relative-time 5`

- Reflect on access denied errors for all roles:

  `cloudig reflect iam -i 'arn:aws:iam::111111111111:role/lp-iam-prismacloud' --errors`

```
[ℹ]  reading comments from file comments.yaml
[ℹ]  working on reflect report for account: 111111111111
[ℹ]  getting the s3 prefix associated with the CloudTrail
[ℹ]  constructing the Athena table metadata form the s3 prefix
[ℹ]  finding the existing Athena table from the constructed metadata
[ℹ]  found the existing Athena table: default.reflect_cloudtrail_gxev4
[ℹ]  populating findings for roles
[✔]  successfully polpulated the findings for roles
[ℹ]  finding the actual permission for the roles
[✔]  reflecting on account 111111111111 took 19.180778089s
{
  "findings": [
    {
      "accountId": "111111111111",
      "IAMIdentity": "arn:aws:iam::111111111111:role/lp-iam-prismacloud",
      "accessDetails": [
        {
          "IAMAction": "wafv2.amazonaws.com/GetWebACL/AccessDenied",
          "UsageCount": 612
        },
        {
          "IAMAction": "inspector.amazonaws.com/DescribeAssessmentRuns/AccessDenied",
          "UsageCount": 268
        },
        {
          "IAMAction": "kms.amazonaws.com/DescribeKey/AccessDenied",
          "UsageCount": 103
        },
        {
          "IAMAction": "dms.amazonaws.com/DescribeCertificates/AccessDenied",
          "UsageCount": 34
        },
        {
          "IAMAction": "directconnect.amazonaws.com/DescribeConnections/AccessDenied",
          "UsageCount": 34
        }
      ],
      "permissionSet": [
        "iam:listSAMLProviders",
        "iam:getSAMLProvider",
        "iam:SimulatePrincipalPolicy",
        "iam:SimulateCustomPolicy",
        "iam:ListVirtualMFADevices",
        "iam:ListUsers",
        "iam:ListUserTags",
        "iam:ListUserPolicies",
        "iam:ListServerCertificates",
        "iam:ListSSHPublicKeys",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:ListPolicyVersions",
        "iam:ListPolicies",
        "iam:ListMFADevices",
        "iam:ListInstanceProfilesForRole",
        "iam:ListGroupsForUser",
        "iam:ListGroups",
        "iam:ListGroupPolicies",
        "iam:ListEntitiesForPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAccessKeys",
        "iam:GetUserPolicy",
        "iam:GetServiceLastAccessedDetails",
        "iam:GetRolePolicy",
        "iam:GetPolicyVersion",
        "iam:GetGroupPolicy",
        "iam:GetCredentialReport",
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountAuthorizationDetails",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GenerateCredentialReport",
        "guardduty:ListFindings",
        "guardduty:ListDetectors",
        "guardduty:GetFindings",
        "guardduty:GetDetector",
        "glue:GetSecurityConfigurations",
        "glue:GetConnections",
        "glacier:ListVaults",
        "glacier:ListTagsForVault",
        "glacier:GetVaultNotifications",
        "glacier:GetVaultLock",
        "glacier:GetVaultAccessPolicy",
        "glacier:GetDataRetrievalPolicy",
        "fms:ListPolicies",
        "fms:ListComplianceStatus",
        "firehose:ListTagsForDeliveryStream",
        "firehose:ListDeliveryStreams",
        "firehose:DescribeDeliveryStream",
        "es:ListTags",
        "es:ListDomainNames",
        "es:DescribeElasticsearchDomains",
        "elasticmapreduce:ListSecurityConfigurations",
        "elasticmapreduce:ListClusters",
        "elasticmapreduce:GetBlockPublicAccessConfiguration",
        "elasticmapreduce:DescribeSecurityConfiguration",
        "elasticmapreduce:DescribeCluster",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeSSLPolicies",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerPolicies",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeListeners",
        "elasticfilesystem:DescribeTags",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:DescribeMountTargetSecurityGroups",
        "elasticfilesystem:DescribeFileSystems",
        "elasticbeanstalk:ListTagsForResource",
        "elasticbeanstalk:DescribeEnvironments",
        "elasticbeanstalk:DescribeEnvironmentResources",
        "elasticbeanstalk:DescribeConfigurationSettings",
        "elasticache:ListTagsForResource",
        "elasticache:DescribeSnapshots",
        "elasticache:DescribeReservedCacheNodesOfferings",
        "elasticache:DescribeReservedCacheNodes",
        "elasticache:DescribeReplicationGroups",
        "elasticache:DescribeCacheSubnetGroups",
        "elasticache:DescribeCacheSecurityGroups",
        "elasticache:DescribeCacheParameterGroups",
        "elasticache:DescribeCacheEngineVersions",
        "elasticache:DescribeCacheClusters",
        "eks:ListTagsForResource",
        "eks:ListClusters",
        "eks:DescribeCluster",
        "ecs:ListTasks",
        "ecs:ListTaskDefinitions",
        "ecs:ListTagsForResource",
        "ecs:ListServices",
        "ecs:ListClusters",
        "ecs:DescribeTasks",
        "ecs:DescribeTaskDefinition",
        "ecs:DescribeServices",
        "ecr:ListTagsForResource",
        "ecr:GetRepositoryPolicy",
        "ecr:GetLifecyclePolicy",
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "ec2:DescribeVpnGateways",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVolumes",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTags",
        "ec2:DescribeSubnets",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSnapshotAttribute",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "ec2:DescribeRegions",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeNetworkInterfaceAttribute",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNatGateways",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeImages",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeDhcpOptions",
        "ec2:DescribeCustomerGateways",
        "ec2:DescribeAddresses",
        "ec2:DescribeAccountAttributes",
        "dynamodb:ListTagsOfResource",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "ds:DescribeDirectories",
        "dms:ListTagsForResource",
        "dms:DescribeReplicationInstances",
        "dms:DescribeEndpoints",
        "directconnect:DescribeDirectConnectGateways",
        "config:DescribeDeliveryChannels",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:BatchGetResourceConfig",
        "config:BatchGetAggregateResourceConfig",
        "cognito-idp:ListUserPools",
        "cognito-idp:ListTagsForResource",
        "cognito-identity:ListTagsForResource",
        "cognito-identity:ListIdentityPools",
        "cloudwatch:ListTagsForResource",
        "cloudwatch:ListMetrics",
        "cloudwatch:GetMetricData",
        "cloudwatch:DescribeAlarms",
        "cloudtrail:LookupEvents",
        "cloudtrail:ListTags",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:DescribeTrails",
        "cloudsearch:DescribeDomains",
        "cloudfront:ListTagsForResource",
        "cloudfront:ListDistributions",
        "cloudfront:GetDistributionConfig",
        "cloudformation:ListStacks",
        "cloudformation:ListStackResources",
        "cloudformation:GetTemplate",
        "cloudformation:GetStackPolicy",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackResources",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribeAutoScalingGroups",
        "apigateway:GET",
        "acm:ListTagsForCertificate",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "workspaces:DescribeWorkspaces",
        "workspaces:DescribeWorkspaceDirectories",
        "workspaces:DescribeTags",
        "wafv2:ListWebACLs",
        "wafv2:ListTagsForResource",
        "wafv2:ListResourcesForWebACL",
        "waf:ListWebACLs",
        "waf:ListTagsForResource",
        "waf:GetWebACL",
        "waf:GetLoggingConfiguration",
        "waf-regional:ListWebACLs",
        "waf-regional:ListTagsForResource",
        "waf-regional:ListResourcesForWebACL",
        "tag:GetTagKeys",
        "tag:GetResources",
        "ssm:ListTagsForResource",
        "ssm:ListDocuments",
        "ssm:GetParameters",
        "ssm:DescribeParameters",
        "sqs:listQueueTags",
        "sqs:SendMessage",
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "sns:ListTopics",
        "sns:ListTagsForResource",
        "sns:ListSubscriptionsByTopic",
        "sns:ListSubscriptions",
        "sns:ListPlatformApplications",
        "sns:GetTopicAttributes",
        "sns:GetSubscriptionAttributes",
        "secretsmanager:ListSecrets",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:DescribeSecret",
        "sagemaker:ListTags",
        "sagemaker:ListNotebookInstances",
        "sagemaker:ListEndpoints",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:DescribeEndpoint",
        "s3:ListBucketByTags",
        "s3:ListAllMyBuckets",
        "s3:GetObjectVersionAcl",
        "s3:GetObjectAcl",
        "s3:GetLifecycleConfiguration",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketWebsite",
        "s3:GetBucketVersioning",
        "s3:GetBucketTagging",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPolicy",
        "s3:GetBucketLogging",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetAccountPublicAccessBlock",
        "route53domains:ListTagsForDomain",
        "route53domains:ListOperations",
        "route53domains:ListDomains",
        "route53domains:GetOperationDetail",
        "route53domains:GetDomainDetail",
        "route53:ListTagsForResource",
        "route53:ListResourceRecordSets",
        "route53:ListHostedZones",
        "route53:ListDomains",
        "redshift:DescribeLoggingStatus",
        "redshift:DescribeClusters",
        "redshift:DescribeClusterParameters",
        "rds:ListTagsForResource",
        "rds:DescribeEventSubscriptions",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSnapshotAttributes",
        "rds:DescribeDBParameters",
        "rds:DescribeDBParameterGroups",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBClusterSnapshots",
        "rds:DescribeDBClusterSnapshotAttributes",
        "ram:ListResources",
        "ram:ListPrincipals",
        "ram:GetResourceShares",
        "organizations:DescribeOrganization",
        "mq:ListBrokers",
        "mq:DescribeBroker",
        "logs:ListTagsLogGroup",
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "logs:DescribeMetricFilters",
        "logs:DescribeLogStreams",
        "logs:DescribeLogGroups",
        "lambda:ListTags",
        "lambda:ListLayers",
        "lambda:ListLayerVersions",
        "lambda:ListFunctions",
        "lambda:GetPolicy",
        "lambda:GetLayerVersionPolicy",
        "kms:ListResourceTags",
        "kms:ListKeys",
        "kms:ListKeyPolicies",
        "kms:ListAliases",
        "kms:GetKeyRotationStatus",
        "kms:GetKeyPolicy",
        "kms:DescribeKey",
        "kinesisanalytics:ListApplications",
        "kinesis:ListTagsForStream",
        "kinesis:ListStreams",
        "kinesis:DescribeStream",
        "inspector:ListTagsForResource",
        "inspector:ListRulesPackages",
        "inspector:ListFindings",
        "inspector:ListExclusions",
        "inspector:ListEventSubscriptions",
        "inspector:ListAssessmentTemplates",
        "inspector:ListAssessmentTargets",
        "inspector:ListAssessmentRuns",
        "inspector:ListAssessmentRunAgents",
        "inspector:DescribeRulesPackages",
        "inspector:DescribeFindings",
        "inspector:DescribeAssessmentTemplates"
      ],
      "comments": "NEW_FINDING"
    }
  ],
  "reportTime": "21 Dec 20 13:07 CST"
}
```

- Reflect on all IAM roles:

`cloudig reflect iam`
