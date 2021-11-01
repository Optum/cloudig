package cloudig

import (
	"errors"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestImageScanReports_GetReport(t *testing.T) {
	testCases := []struct {
		name                             string
		accountID                        string
		tag                              string
		region                           string
		getECRImagesWithTagResponse      map[string][]*ecr.ImageDetail
		expectedFindings                 []ImageScanFindings
		getAccountIDError                error
		getECRImagesWithTagResponseError error
		expectedError                    error
	}{
		{
			name:      "Get basic ECR scan report containing all tagged images",
			accountID: "012345678910",
			region:    "us-east-1",
			getECRImagesWithTagResponse: map[string][]*ecr.ImageDetail{
				"012345678910.dkr.ecr.us-east-1.amazonaws.com/app/web-server": {
					{
						ImageTags:      aws.StringSlice([]string{"prod-canary", "test"}),
						ImageDigest:    aws.String("sha256:e0fa362f30aa43f11d1d5e1822ef3117e03782cdd921aaab73267e1219a4fde2"),
						RegistryId:     aws.String("012345678910"),
						RepositoryName: aws.String("app/web-server"),
						ImageScanStatus: &ecr.ImageScanStatus{
							Status: aws.String("COMPLETE"),
						},
						ImageScanFindingsSummary: &ecr.ImageScanFindingsSummary{
							FindingSeverityCounts: map[string]*int64{
								"HIGH":   aws.Int64(2),
								"MEDIUM": aws.Int64(8),
							},
						},
					},
				},
				"012345678910.dkr.ecr.us-east-1.amazonaws.com/app/hello-world": {
					{
						ImageTags:      aws.StringSlice([]string{"test"}),
						ImageDigest:    aws.String("sha256:4e3bc79a145b6bb5756f8f52f60853e842a1681ace8b5115a715c892f4957ea9"),
						RegistryId:     aws.String("012345678910"),
						RepositoryName: aws.String("app/hello-world"),
						ImageScanStatus: &ecr.ImageScanStatus{
							Status: aws.String("FAILED"),
						},
					},
				},
			},
			expectedFindings: []ImageScanFindings{
				{
					AccountID:      "012345678910",
					ImageDigest:    "sha256:e0fa362f30aa43f11d1d5e1822ef3117e03782cdd921aaab73267e1219a4fde2",
					ImageTag:       "prod-canary,test",
					RepositoryName: "app/web-server",
					ImageFindingsCount: map[string]int64{
						"HIGH":   2,
						"MEDIUM": 8,
					},
					Comments: "EXCEPTION Patch will applied this weekend",
					Region:   "us-east-1",
				},
			},
		},
		{
			name:      "Get ECR scan report containing all images having the tag 'test'",
			accountID: "012345678910",
			region:    "us-east-1",
			tag:       "test",
			getECRImagesWithTagResponse: map[string][]*ecr.ImageDetail{
				"012345678910.dkr.ecr.us-east-1.amazonaws.com/app/web-server": {
					{
						ImageTags:      aws.StringSlice([]string{"prod-canary", "test"}),
						ImageDigest:    aws.String("sha256:e0fa362f30aa43f11d1d5e1822ef3117e03782cdd921aaab73267e1219a4fde2"),
						RegistryId:     aws.String("012345678910"),
						RepositoryName: aws.String("app/web-server"),
						ImageScanStatus: &ecr.ImageScanStatus{
							Status: aws.String("COMPLETE"),
						},
						ImageScanFindingsSummary: &ecr.ImageScanFindingsSummary{
							FindingSeverityCounts: map[string]*int64{
								"HIGH":   aws.Int64(2),
								"MEDIUM": aws.Int64(8),
							},
						},
					},
				},
			},
			expectedFindings: []ImageScanFindings{
				{
					AccountID:      "012345678910",
					ImageDigest:    "sha256:e0fa362f30aa43f11d1d5e1822ef3117e03782cdd921aaab73267e1219a4fde2",
					ImageTag:       "test",
					RepositoryName: "app/web-server",
					ImageFindingsCount: map[string]int64{
						"HIGH":   2,
						"MEDIUM": 8,
					},
					Comments: "NEW_FINDING",
					Region:   "us-east-1",
				},
			},
		},
		{
			name:              "Return error while retrieving the AccountID",
			getAccountIDError: errors.New("Some API error"),
			expectedError:     errors.New("Some API error"),
		},
		{
			name:                             "Return error while retrieving tagged image information",
			accountID:                        "012345678910",
			getECRImagesWithTagResponseError: errors.New("Some API error"),
			expectedError:                    errors.New("Some API error"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			mockAPIs.EXPECT().GetAccountID().Return(tc.accountID, tc.getAccountIDError).MaxTimes(1)
			mockAPIs.EXPECT().GetECRImagesWithTag(tc.tag).Return(tc.getECRImagesWithTagResponse, tc.getECRImagesWithTagResponseError).MaxTimes(1)
			// Use comments file for testing
			comments := parseCommentsFile("../../test/data/comments.yaml")

			report := &ImageScanReports{
				Flags: ImageScanReportFlags{
					Tag:    tc.tag,
					Region: tc.region,
				},
			}
			err := report.GetReport(mockAPIs, comments)

			assert.ElementsMatch(t, tc.expectedFindings, report.Findings)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
