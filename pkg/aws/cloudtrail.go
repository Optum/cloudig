package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

// CloudTrailSVC is a wrapper for CloudTrail service API calls
type CloudTrailSVC interface {
	GetS3LogPrefixForCloudTrail() (*string, error)
}

// GetS3LogPrefixForCloudTrail retruns a S3Prefix associated with CloudTrail if one available for a region derived from the authenticated session
// and an error if there is any
// https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-find-log-files.html
func (client *Client) GetS3LogPrefixForCloudTrail() (*string, error) {
	accountID, err := client.GetAccountID()
	if err != nil {
		return nil, err
	}
	fixedPrefix := "/AWSLogs/" + accountID + "/CloudTrail"
	result, err := client.CloudTrail.DescribeTrails(&cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}
	if len(result.TrailList) > 0 {
		for _, t := range result.TrailList {
			if t.S3BucketName != nil {
				return aws.String("s3://" + aws.StringValue(t.S3BucketName) + "/" + aws.StringValue(t.S3KeyPrefix) + fixedPrefix), nil
			}
		}
	}
	return nil, nil
}
