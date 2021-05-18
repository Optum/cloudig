package aws

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/Optum/cloudig/pkg/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go/service/health"
)

func TestGetHealthEvents(t *testing.T) {
	testCases := []struct {
		name          string
		input         *string
		output        *health.DescribeEventsOutput
		expectedError error
	}{
		{
			name:  "Return Events with a next token",
			input: aws.String("a token"),
			output: &health.DescribeEventsOutput{
				Events: []*health.Event{{
					Arn: aws.String("arn1"),
				}},
			},
			expectedError: nil,
		},
		{
			name:  "Return Events with no next token",
			input: nil,
			output: &health.DescribeEventsOutput{
				Events: []*health.Event{{
					Arn: aws.String("arn1"),
				}},
			},
			expectedError: nil,
		},
		{
			name:          "Return error",
			input:         nil,
			output:        nil,
			expectedError: errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockHealthAPI := mocks.NewMockHealthAPI(mockCtrl)
			mockHealthAPI.EXPECT().DescribeEvents(&health.DescribeEventsInput{
				Filter: &health.EventFilter{
					EventTypeCategories: []*string{aws.String("accountNotification")},
					EventStatusCodes:    []*string{aws.String("open"), aws.String("upcoming")},
				},
				MaxResults: aws.Int64(100),
				NextToken:  tc.input,
			}).Return(tc.output, tc.expectedError)
			client := &Client{
				Health: mockHealthAPI,
			}

			output, err := client.GetHealthEvents(nil, tc.input)
			assert.Equal(t, tc.output, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestGetHealthEventDetails(t *testing.T) {
	testCases := []struct {
		name          string
		input         []*string
		output        *health.DescribeEventDetailsOutput
		expectedError error
	}{
		{
			name:  "Return Events with a next token",
			input: []*string{aws.String("arn1"), aws.String("arn2")},
			output: &health.DescribeEventDetailsOutput{
				SuccessfulSet: []*health.EventDetails{
					{
						Event: &health.Event{
							Arn: aws.String("arn1"),
						},
					},
					{
						Event: &health.Event{
							Arn: aws.String("arn2"),
						},
					},
				},
			},
			expectedError: nil,
		},
		{
			name:          "Return error",
			input:         []*string{aws.String("arn1"), aws.String("arn2")},
			output:        nil,
			expectedError: errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockHealthAPI := mocks.NewMockHealthAPI(mockCtrl)
			mockHealthAPI.EXPECT().DescribeEventDetails(&health.DescribeEventDetailsInput{
				EventArns: []*string{aws.String("arn1"), aws.String("arn2")},
			}).Return(tc.output, tc.expectedError)
			client := &Client{
				Health: mockHealthAPI,
			}

			output, err := client.GetHealthEventDetails(tc.input)
			assert.Equal(t, tc.output, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
	// test case where function is not hit
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockHealthAPI := mocks.NewMockHealthAPI(mockCtrl)
	client := &Client{
		Health: mockHealthAPI,
	}
	output, err := client.GetHealthEventDetails(nil)
	var outputNilType *health.DescribeEventDetailsOutput
	assert.Equal(t, outputNilType, output)
	assert.Equal(t, errors.New("Describe event details can only query for 1-10 event details at a time"), err)
}

func TestGetHealthAffectedEntities(t *testing.T) {
	testCases := []struct {
		name           string
		inputArnArr    []*string
		inputNextToken *string
		output         *health.DescribeAffectedEntitiesOutput
		expectedError  error
	}{
		{
			name:           "Return Events with a next token",
			inputArnArr:    []*string{aws.String("arn1"), aws.String("arn2")},
			inputNextToken: aws.String("Some token"),
			output: &health.DescribeAffectedEntitiesOutput{
				Entities: []*health.AffectedEntity{
					{
						EventArn: aws.String("arn1"),
					},
					{
						EventArn: aws.String("arn2"),
					},
				},
			},
			expectedError: nil,
		},
		{
			name:           "Return error",
			inputArnArr:    []*string{aws.String("arn1"), aws.String("arn2")},
			inputNextToken: aws.String("Some token"),
			output:         nil,
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockHealthAPI := mocks.NewMockHealthAPI(mockCtrl)
			mockHealthAPI.EXPECT().DescribeAffectedEntities(&health.DescribeAffectedEntitiesInput{
				Filter: &health.EntityFilter{
					EventArns: tc.inputArnArr,
				},
				NextToken: tc.inputNextToken,
			}).Return(tc.output, tc.expectedError)
			client := &Client{
				Health: mockHealthAPI,
			}

			output, err := client.GetHealthAffectedEntities(tc.inputArnArr, tc.inputNextToken)
			assert.Equal(t, tc.output, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
	// test case where function is not hit
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockHealthAPI := mocks.NewMockHealthAPI(mockCtrl)
	client := &Client{
		Health: mockHealthAPI,
	}
	output, err := client.GetHealthAffectedEntities(nil, nil)
	var outputNilType *health.DescribeAffectedEntitiesOutput
	assert.Equal(t, outputNilType, output)
	assert.Equal(t, errors.New("Describe affected entities can only query for 1-100 event details at a time"), err)
}
