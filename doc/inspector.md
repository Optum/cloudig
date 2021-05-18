Inspector: `inspector`, `ins`, `i`

Example: `cloudig get inspector --cfile my-comments.yaml --output mdtable`

Output (Markdown Table)

```markdown
Report Time: 11 Oct 19 13:32 CDT

| ACCOUNT ID   | TEMPLATE NAME   | RULE PACKAGES                 | HIGH | MEDIUM | LOW | INFORMATIONAL | COMMENTS                   |
| ------------ | --------------- | ----------------------------- | ---- | ------ | --- | ------------- | -------------------------- |
| 111111111111 | test-once-dev   | CIS Operating System Security | 267  | 0      | 0   | 24            | **EXCEPTION:** Description |
|              |                 | Configuration Benchmarks-1.0  |      |        |     |               | here                       |
| 111111111111 | test-once-dev   | Common Vulnerabilities and    | 0    | 0      | 0   | 0             |                            |
|              |                 | Exposures-1.1                 |      |        |     |               |                            |
| 111111111111 | test-once-dev   | Security Best Practices-1.0   | 0    | 3      | 0   | 0             | NEW_FINDING                |
| 111111111111 | k8s_weekly_scan | Network Reachability-1.1      | 0    | 0      | 0   | 0             |                            |

| ACCOUNT ID   | AMI                            | AGE     |
| ------------ | ------------------------------ | ------- |
| 111111111111 | amazon-eks-node-1.16-v20201211 | 25 days |
|              |                                |         |
```
