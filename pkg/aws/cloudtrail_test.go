package aws

import (
	"errors"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetCloudTrailWithS3Prefix(t *testing.T) {
	// sess, _ := NewAuthenticatedSession("us-east-2")
	// prefix, err := NewClient(sess).GetCloudTrailWithS3Prefix()
	// if err != nil {
	// 	log.Println(err)
	// }
	// log.Println(prefix)
	// t.Fail()

	testCases := []struct {
		name           string
		apiResponse    *cloudtrail.DescribeTrailsOutput
		expectedOutput *string
		expectedError  error
	}{
		{
			name:           "emptyResponse#1",
			apiResponse:    &cloudtrail.DescribeTrailsOutput{},
			expectedOutput: nil,
			expectedError:  nil,
		},
		{
			name: "Trial WithOut S3",
			apiResponse: &cloudtrail.DescribeTrailsOutput{
				TrailList: []*cloudtrail.Trail{
					{
						Name:                       aws.String("myTestTrail"),
						HomeRegion:                 aws.String("us-east-1"),
						IncludeGlobalServiceEvents: aws.Bool(true),
						IsMultiRegionTrail:         aws.Bool(true),
						TrailARN:                   aws.String("arn:aws:cloudtrail:us-east-1:378456495793:trail/myTestTrail"),
					},
				},
			},
			expectedOutput: nil,
			expectedError:  nil,
		},
		{
			name: "trialWithS3#2",
			apiResponse: &cloudtrail.DescribeTrailsOutput{
				TrailList: []*cloudtrail.Trail{
					{
						Name:                       aws.String("myTestTrail"),
						HomeRegion:                 aws.String("us-east-1"),
						IncludeGlobalServiceEvents: aws.Bool(true),
						IsMultiRegionTrail:         aws.Bool(true),
						TrailARN:                   aws.String("arn:aws:cloudtrail:us-east-1:111111111111:trail/myTestTrail"),
					},
					{
						Name:                       aws.String("myTestTrail1"),
						HomeRegion:                 aws.String("us-east-1"),
						IncludeGlobalServiceEvents: aws.Bool(true),
						IsMultiRegionTrail:         aws.Bool(true),
						S3BucketName:               aws.String("lp-cl-111111111111-us-east-1"),
						S3KeyPrefix:                aws.String("source=aws/account=111111111111/region=us-east-1/service=cloudtrail"),
						TrailARN:                   aws.String("arn:aws:cloudtrail:us-east-1:111111111111:trail/myTestTrail1"),
					},
				},
			},
			expectedOutput: aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
			expectedError:  nil,
		},
		{
			name:           "errorResponse#3",
			apiResponse:    nil,
			expectedOutput: nil,
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockCloudTrailAPI := mocks.NewMockCloudTrailAPI(mockCtrl)

			mockCloudTrailAPI.EXPECT().DescribeTrails(&cloudtrail.DescribeTrailsInput{}).Return(tc.apiResponse, tc.expectedError)

			mockSTSAPI := mocks.NewMockSTSAPI(mockCtrl)
			mockSTSAPI.EXPECT().GetCallerIdentity(&sts.GetCallerIdentityInput{}).Return(&sts.GetCallerIdentityOutput{
				Account: aws.String("111111111111"),
				Arn:     aws.String("arn:aws:sts::111111111111:assumed-role/AWS_111111111111_ReadOnly/test@gmail.com"),
				UserId:  aws.String("AROAIU4J2NPCGYXQIOPMQ:test@gmail.com"),
			}, nil)

			client := &Client{
				CloudTrail: mockCloudTrailAPI,
				STS:        mockSTSAPI,
			}

			output, err := client.GetS3LogPrefixForCloudTrail()
			assert.Equal(t, aws.StringValue(tc.expectedOutput), aws.StringValue(output))
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
