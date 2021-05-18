AWS Config: `awsconfig`, `ac`, `a`

Example: `cloudig get ac --region us-east-1 -o table`

Output (ASCII Table)

```txt
Report Time:  11 Oct 19 13:27 CDT

+--------------+---------------------------------------------+--------------------------------+-------------+
|  ACCOUNT ID  |                    NAME                     |       FLAGGED RESOURCES        |  COMMENTS   |
+--------------+---------------------------------------------+--------------------------------+-------------+
| 123456789101 | ALL_OPEN_INBOUND_PORTS_SECURITY_GROUP_CHECK | Resource Type:                 | NEW_FINDING |
|              |                                             | AWS::EC2::SecurityGroup        |             |
|              |                                             | sg-111111                      |             |
|              |                                             | sg-222222                      |             |
+--------------+---------------------------------------------+--------------------------------+-------------+
| 123456789101 | ATTACHED_INTERNET_GATEWAY_CHECK             | Resource Type: AWS::EC2::VPC   | NEW_FINDING |
|              |                                             | vpc-11111          |           |
|              |                                             | vpc-22222 vpc-333333           |             |
+--------------+---------------------------------------------+--------------------------------+-------------+
| 123456789101 | CF_WITH_S3_ORIGIN_ONLY_ALLOWS_CF_READ_CHECK | Resource Type:                 | NEW_FINDING |
|              |                                             | AWS::CloudFront::Distribution  |             |
|              |                                             | {CFDistroID} {CFDistroID}      |             |
+--------------+---------------------------------------------+--------------------------------+-------------+
```
