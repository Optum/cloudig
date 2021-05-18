package aws

import (
	"errors"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
)

func TestGetAccountID(t *testing.T) {
	testCases := []struct {
		name           string
		apiResponse    *sts.GetCallerIdentityOutput
		expectedOutput string
		expectedError  error
	}{
		{
			name: "Return Account ID",
			apiResponse: &sts.GetCallerIdentityOutput{
				Account: aws.String("012345678910"),
				Arn:     aws.String("arn:aws:sts::012345678910:assumed-role/AWS_012345678910_ReadOnly/test@gmail.com"),
				UserId:  aws.String("AROAIU4J2NPCGYXQIOPMQ:test@gmail.com"),
			},
			expectedOutput: "012345678910",
			expectedError:  nil,
		},
		{
			name:           "Return error",
			apiResponse:    &sts.GetCallerIdentityOutput{},
			expectedOutput: "",
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockSTSAPI := mocks.NewMockSTSAPI(mockCtrl)
			mockSTSAPI.EXPECT().GetCallerIdentity(&sts.GetCallerIdentityInput{}).Return(tc.apiResponse, tc.expectedError)
			client := &Client{
				STS: mockSTSAPI,
			}

			output, err := client.GetAccountID()
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
