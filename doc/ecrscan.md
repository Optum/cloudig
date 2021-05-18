AWS ECR Image scan findings : `ecrscan`, `scan`, `s`

Example: `cloudig get scan --region us-east-1 -o json`

Sample Output(JSON)

```json
{
  "findings": [
    {
      "accountId": "333333333333",
      "imageDigest": "sha256:88d5da4609681df482d51c4e898d107317c32bd3c4951793138570cc18c1294d",
      "imageTag": "latest",
      "repositoryName": "dig/pingfederate-server",
      "region": "us-east-1",
      "comments": "NEW_FINDING",
      "imageFindingsCount": {
        "HIGH": 1
      }
    },
    {
      "accountId": "333333333333",
      "imageDigest": "sha256:99d0ab34e24a87884b104e76dea5d917ab026c0cfc352bc9cf2665d5d70f973a",
      "imageTag": "v0.0.16",
      "repositoryName": "dig/service-gateway",
      "region": "us-east-1",
      "comments": "**EXCEPTION** Patch will applied this weekend",
      "imageFindingsCount": {
        "HIGH": 5,
        "MEDIUM": 4
      }
    }
  ]
}
```

esrscan image will also take optional parameter tag as first argument:

```
cloudig get scan --tag <tag> -o mdtable

Example:
cloudig get scan --tag latest -o mdtable
```

```markdown
Sample output with mdtable format, with specific tag "latest"

| ACCOUNT ID   | REGION    | REPOSITORY NAME                     | TAG    | VULNERABILITIES(COUNT) | COMMENTS    |
| ------------ | --------- | ----------------------------------- | ------ | ---------------------- | ----------- |
| 111111111111 | us-east-1 | temporary-custom-terraform-provider | latest | LOW: 6                 | NEW_FINDING |
|              |           |                                     |        | HIGH: 18               |             |
|              |           |                                     |        | MEDIUM: 19             |             |
```
