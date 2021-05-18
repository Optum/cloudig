Trusted Advisor: `trustedadvisor`, `ta`, `t`

Example: `cloudig get ta --rolearn arn:aws:iam::678910:role/cloudig`

Output (JSON)

```json
{
  "findings": [
    {
      "accountId": "123456",
      "category": "COST_OPTIMIZING",
      "name": "Low Utilization Amazon EC2 Instances",
      "description": "Checks the Amazon Elastic Compute Cloud (Amazon EC2) instances that were running at any time during the last 14 days and alerts you if the daily CPU utilization was 10% or less and network I/O was 5 MB or less on 4 or more days. Running instances generate hourly usage charges. Although some scenarios can result in low utilization by design, you can often lower your costs by managing the number and size of your instances.",
      "status": "warning",
      "resourcesSummary": {
        "ResourcesFlagged": 16,
        "ResourcesIgnored": 0,
        "ResourcesProcessed": 37,
        "ResourcesSuppressed": 0
      },
      "flaggedResources": [
        "i-0b18439757faf088a",
        "i-095d0079d8546fd8a",
        "i-0c5b586ec7e9d7eac",
        "i-0e83db48d6de8f40b",
        "i-008cceaa442471ec0",
        "i-00699354adf9984ad",
        "i-076d00ae185881b57",
        "i-06faf0349948904c2",
        "i-0baaf4989f05861aa",
        "i-05663b1bc7e34230f",
        "i-0928ccca5a6be3bab",
        "i-0bd17acfcd8fd0545",
        "i-0a23e343bb9fceb02",
        "i-05b2809ba8bdd0b2c",
        "i-04ebe8cc56724dda7",
        "i-00ea85d920e9dd8cf"
      ],
      "comments": "NEW_FINDING"
    },
    {
      "accountId": "678910",
      "category": "SECURITY",
      "name": "IAM Use",
      "description": "Checks for your use of AWS Identity and Access Management (IAM). You can use IAM to create users, groups, and roles in AWS, and you can use permissions to control access to AWS resources.",
      "status": "warning",
      "resourcesSummary": {
        "ResourcesFlagged": 1,
        "ResourcesIgnored": 0,
        "ResourcesProcessed": 1,
        "ResourcesSuppressed": 0
      },
      "flaggedResources": [
        "NA"
      ],
      "comments": "**EXCEPTION:** We use Federation and IAM roles to manage resources in AWS . No users/groups created in IAM"
    },
  ],
  "reportTime": "08 Oct 19 10:44 CDT"
```
