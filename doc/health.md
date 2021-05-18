Health: `health`, `he`, `h`

Example: `cloudig get health --cfile my-comments.yaml --output mdtable`

Output (Markdown Table)

```markdown
| ACCOUNT ID   | EVENT TYPE CODE              | REGION    | STATUS CODE | EVENT DESCRIPTION              | AFFECTED RESOURCES               | COMMENTS    |
| ------------ | ---------------------------- | --------- | ----------- | ------------------------------ | -------------------------------- | ----------- |
| 111111111111 | Rds Operational Notification | us-east-2 | open        | On December 4, 2020, we        | dig-global-stage-aurora-cluster, | NEW_FINDING |
|              |                              |           |             | sent an email that contained   | dig-global-dev-aurora-cluster    |             |
|              |                              |           |             | errors in formatting. We have  |                                  |             |
|              |                              |           |             | corrected these issues and     |                                  |             |
|              |                              |           |             | are resending the email in     |                                  |             |
|              |                              |           |             | its entirety following this    |                                  |             |
|              |                              |           |             | paragraph. We are sorry for    |                                  |             |
|              |                              |           |             | any inconvenience our mistake  |                                  |             |
|              |                              |           |             | may have caused.Our records    |                                  |             |
|              |                              |           |             | indicate that you have one     |                                  |             |
|              |                              |           |             | or more Aurora MySQL database  |                                  |             |
|              |                              |           |             | instances which are not        |                                  |             |
|              |                              |           |             | running the latest preferred   |                                  |             |
|              |                              |           |             | minor version of Aurora MySQL  |                                  |             |
|              |                              |           |             | (with MySQL 5.6 compatibility) |                                  |             |
|              |                              |           |             | available on RDS.              |                                  |             |
| 111111111111 | Ecs Operational Notification | us-east-1 | open        | A software update has been     | dig-dev-kafka-service-0          | NEW_FINDING |
|              |                              |           |             | deployed to the AWS Fargate    | / dig-dev-kafka-cluster,         |             |
|              |                              |           |             | infrastructure. Your impacted  | dig-dev-kafka-service-2          |             |
|              |                              |           |             | Amazon ECS services in the     | / dig-dev-kafka-cluster,         |             |
|              |                              |           |             | US-EAST-1 Region are listed    | dev-exodos / dev-exodos,         |             |
|              |                              |           |             | in your 'Affected resources'   | dig-dev-kafka-service-1          |             |
|              |                              |           |             | tab in the format Service /    | / dig-dev-kafka-cluster,         |             |
|              |                              |           |             | Cluster.This software update   | stage-exodos / stage-exodos,     |             |
|              |                              |           |             | requires that the tasks in     | okra-exodos / okra-exodos,       |             |
|              |                              |           |             | your affected services be      | dig-stage-kafka-service-1        |             |
|              |                              |           |             | relaunched by forcing a new    | / dig-stage-kafka-cluster,       |             |
|              |                              |           |             | service deployment. You can    | dig-stage-kafka-service-0        |             |
|              |                              |           |             | update your service and force  | / dig-stage-kafka-cluster,       |             |
|              |                              |           |             | a new service deployment using | dig-stage-kafka-service-2 /      |             |
|              |                              |           |             | the AWS Management Console,    | dig-stage-kafka-cluster          |             |
|              |                              |           |             | AWS SDKs, or the AWS CLI.      |
```
