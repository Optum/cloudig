AWS ECR Image scan findings : `ecrscan`, `scan`, `s`

Example: `cloudig get scan --region us-east-1 -o json`

Sample Output(JSON)

```json
{
  "findings": [
     {
      "accountId": "3333333333333",
      "imageDigest": "sha256:b20c71bdd914b436f9d4745cb5392cd86c3e2esd4517f5cc442060a1ec3193ed",
      "imageTag": "stage-2021-09-28.060926,prod-2021-10-09.031013,deploy-2.3,nonprod-2021-10-07.01",
      "repositoryName": "dig/sample-server",
      "imageFindingsCount": {
        "MEDIUM": 8
      },
      "comments": "NEW_FINDING",
      "region": "us-east-1"
    },
    {
      "accountId": "3333333333333",
      "imageDigest": "sha256:33f43a94fdac3b494ae340c964facaead8b83b0arebddefd65de08c98c7c6fcf4",
      "imageTag": "prod-2021-09-06.01,nonprod-2021-09-03.1,release-P8-1",
      "repositoryName": "dig/sample-server",
      "imageFindingsCount": {
        "HIGH": 1,
        "LOW": 2,
        "MEDIUM": 18
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

| ACCOUNT ID   | REGION    | REPOSITORY NAME                               | TAG                                                                                                                       | VULNERABILITIES(COUNT) | COMMENTS    |
|--------------|-----------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|------------------------|-------------|
| 111111111111 | us-east-1 | dig/sample-server                             | alpha-2.17.1-pr-394.2                                                                                                     | MEDIUM:         9      | NEW_FINDING |
|              |           |                                               |                                                                                                                           | HIGH:           1      |             |
|              |           |                                               | alpha-2.18.1-pr-393.10                                                                                                    | MEDIUM:         9      | NEW_FINDING |
|              |           |                                               |                                                                                                                           | HIGH:           1      |             |
|              |           |                                               | alpha-2.17.1-pr-394.1                                                                                                     | MEDIUM:         9      | NEW_FINDING |
|              |           |                                               |                                                                                                                           | HIGH:           1      |             |
|              |           |                                               | stage-2021-09-28.060926,prod-2021-10-08.031013,deploy-2.15.1-3,nonprod-2021-10-07.051031                                  | MEDIUM:         8      | NEW_FINDING |
|              |           |                                               | prod-2021-09-06.020935,nonprod-2021-09-03.040916,release-P84-1                                                            | LOW:            2      | NEW_FINDING |
|              |           |                                               |                                                                                                                           | HIGH:           1      |             |
|              |           |                                               |                                                                                                                           | MEDIUM:         18     |             |

```
