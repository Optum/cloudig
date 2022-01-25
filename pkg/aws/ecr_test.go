package aws

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/golang/mock/gomock"
)

func TestClient_GetECRImagesWithTag(t *testing.T) {
	tests := []struct {
		name                               string
		tag                                string
		describeRepositoriesResponses      []*ecr.DescribeRepositoriesOutput
		describeRepositoriesResponsesError error
		describeImagesResponses            []*ecr.DescribeImagesOutput
		describeImagesResponsesError       error
		want                               map[string][]*ecr.ImageDetail
		wantErr                            bool
	}{
		{
			name: "Return all images with tag",
			tag:  "test",
			describeRepositoriesResponses: []*ecr.DescribeRepositoriesOutput{
				{
					NextToken: aws.String("123"),
					Repositories: []*ecr.Repository{
						{
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
							RepositoryUri:  aws.String("012345678910.dkr.ecr.us-east-1.amazonaws.com/app/web-server"),
						},
					},
				},
				{
					Repositories: []*ecr.Repository{
						{
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/hello-world"),
							RepositoryUri:  aws.String("012345678910.dkr.ecr.us-east-1.amazonaws.com/app/hello-world"),
						},
					},
				},
			},
			describeImagesResponses: []*ecr.DescribeImagesOutput{
				{
					NextToken: aws.String("456"),
					ImageDetails: []*ecr.ImageDetail{
						{
							ImageTags:      aws.StringSlice([]string{"v1"}),
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
						},
						{
							ImageTags:      aws.StringSlice([]string{"stage-canary", "test"}),
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
						},
					},
				},
				{
					ImageDetails: []*ecr.ImageDetail{
						{
							ImageTags:      aws.StringSlice([]string{"prod-canary"}),
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
						},
					},
				},
				{
					ImageDetails: []*ecr.ImageDetail{
						{
							ImageTags:      aws.StringSlice([]string{"test"}),
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/hello-world"),
						},
					},
				},
			},
			want: map[string][]*ecr.ImageDetail{
				"012345678910.dkr.ecr.us-east-1.amazonaws.com/app/web-server": {
					{
						ImageTags:      aws.StringSlice([]string{"stage-canary", "test"}),
						RegistryId:     aws.String("012345678910"),
						RepositoryName: aws.String("app/web-server"),
					},
				},
				"012345678910.dkr.ecr.us-east-1.amazonaws.com/app/hello-world": {
					{
						ImageTags:      aws.StringSlice([]string{"test"}),
						RegistryId:     aws.String("012345678910"),
						RepositoryName: aws.String("app/hello-world"),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Return all tagged images when no specific tag specified",
			describeRepositoriesResponses: []*ecr.DescribeRepositoriesOutput{
				{
					Repositories: []*ecr.Repository{
						{
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
							RepositoryUri:  aws.String("012345678910.dkr.ecr.us-east-1.amazonaws.com/app/web-server"),
						},
					},
				},
			},
			describeImagesResponses: []*ecr.DescribeImagesOutput{
				{
					NextToken: aws.String("456"),
					ImageDetails: []*ecr.ImageDetail{
						{
							ImageTags:      aws.StringSlice([]string{"v1"}),
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
						},
						{
							ImageTags:      aws.StringSlice([]string{"stage-canary", "test"}),
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
						},
					},
				},
				{
					ImageDetails: []*ecr.ImageDetail{
						{
							ImageTags:      aws.StringSlice([]string{"prod-canary"}),
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
						},
					},
				},
			},
			want: map[string][]*ecr.ImageDetail{
				"012345678910.dkr.ecr.us-east-1.amazonaws.com/app/web-server": {
					{
						ImageTags:      aws.StringSlice([]string{"v1"}),
						RegistryId:     aws.String("012345678910"),
						RepositoryName: aws.String("app/web-server"),
					},
					{
						ImageTags:      aws.StringSlice([]string{"stage-canary", "test"}),
						RegistryId:     aws.String("012345678910"),
						RepositoryName: aws.String("app/web-server"),
					},
					{
						ImageTags:      aws.StringSlice([]string{"prod-canary"}),
						RegistryId:     aws.String("012345678910"),
						RepositoryName: aws.String("app/web-server"),
					},
				},
			},
			wantErr: false,
		},
		{
			name:                               "Return error if DescribeRepositories call fails",
			describeRepositoriesResponsesError: errors.New("some API error"),
			want:                               nil,
			wantErr:                            true,
		},
		{
			name: "Return error if DescribeImages call fails",
			describeRepositoriesResponses: []*ecr.DescribeRepositoriesOutput{
				{
					Repositories: []*ecr.Repository{
						{
							RegistryId:     aws.String("012345678910"),
							RepositoryName: aws.String("app/web-server"),
							RepositoryUri:  aws.String("012345678910.dkr.ecr.us-east-1.amazonaws.com/app/web-server"),
						},
					},
				},
			},
			describeImagesResponsesError: errors.New("some API error"),
			want:                         nil,
			wantErr:                      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockECRAPI := mocks.NewMockECRAPI(mockCtrl)

			// Simulate responses from ECR APIs
			if len(tt.describeRepositoriesResponses) > 0 {
				for _, resp := range tt.describeRepositoriesResponses {
					mockECRAPI.EXPECT().DescribeRepositories(gomock.Any()).Return(resp, tt.describeRepositoriesResponsesError).MaxTimes(1)
				}
			} else {
				mockECRAPI.EXPECT().DescribeRepositories(gomock.Any()).Return(nil, tt.describeRepositoriesResponsesError).MaxTimes(1)
			}

			if len(tt.describeImagesResponses) > 0 {
				for _, resp := range tt.describeImagesResponses {
					mockECRAPI.EXPECT().DescribeImages(gomock.Any()).Return(resp, tt.describeImagesResponsesError).MaxTimes(1)
				}
			} else {
				mockECRAPI.EXPECT().DescribeImages(gomock.Any()).Return(nil, tt.describeImagesResponsesError).MaxTimes(1)
			}

			client := &Client{
				ECR: mockECRAPI,
			}

			got, err := client.GetECRImagesWithTag(tt.tag)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetECRImagesWithTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetECRImagesWithTag() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_GetECRImageScanFindings(t *testing.T) {
	testCases := []struct {
		name                            string
		image                           *ecr.ImageDetail
		describeImageScanFindingsOutput *ecr.DescribeImageScanFindingsOutput
		scanFindingsMap                 map[string]int64
	}{
		{
			name:                            "test case with empty image details",
			image:                           nil,
			scanFindingsMap:                 nil,
			describeImageScanFindingsOutput: nil,
		}, {
			name: "test case with valid image details",
			image: &ecr.ImageDetail{
				ImageTags:      aws.StringSlice([]string{"prod-canary"}),
				RegistryId:     aws.String("012345678910"),
				RepositoryName: aws.String("app/web-server"),
				ImageDigest:    aws.String("prod-canary-image-digest"),
			},
			describeImageScanFindingsOutput: &ecr.DescribeImageScanFindingsOutput{
				ImageScanStatus: &ecr.ImageScanStatus{
					Status: aws.String("COMPLETE"),
				},
				ImageScanFindings: &ecr.ImageScanFindings{
					FindingSeverityCounts: map[string]*int64{
						"MEDIUM":   aws.Int64(1),
						"CRITICAL": aws.Int64(1),
					},
				},
			},
			scanFindingsMap: map[string]int64{
				"MEDIUM":   1,
				"CRITICAL": 1,
			},
		},
	}
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockECRAPI := mocks.NewMockECRAPI(mockCtrl)
			if test.image != nil {
				mockECRAPI.EXPECT().DescribeImageScanFindings(gomock.Any()).Return(test.describeImageScanFindingsOutput, nil).MaxTimes(1)
			}
			client := &Client{
				ECR: mockECRAPI,
			}
			got := client.GetECRImageScanFindings(test.image)
			if !reflect.DeepEqual(got, test.scanFindingsMap) {
				t.Errorf("GetECRImageScanFindings() got = %v, want %v", got, test.scanFindingsMap)
			}
		})
	}
}
