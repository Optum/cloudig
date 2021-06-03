package cloudig

import (
	"errors"
	"io/ioutil"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/sirupsen/logrus"

	"github.com/Optum/cloudig/pkg/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go/service/health"
)

func TestGetHealthReport(t *testing.T) {
	logrus.SetOutput(ioutil.Discard)
	testCases := []struct {
		name               string
		eventInput         []*string
		eventFilter        *health.EventFilter
		eventAPIResponses  []*health.DescribeEventsOutput
		detailInput        [][]*string
		detailAPIResponses []*health.DescribeEventDetailsOutput
		entityInputArn     [][]*string
		entityInputToken   []*string
		entityAPIResponses []*health.DescribeAffectedEntitiesOutput
		expectedOutput     []healthReportFinding
		expectedError      error
	}{
		{
			name:       "Basic Get Report Run",
			eventInput: []*string{nil},
			eventFilter: &health.EventFilter{
				EventTypeCategories: []*string{aws.String("accountNotification")},
				EventStatusCodes:    []*string{aws.String("open"), aws.String("upcoming")},
				LastUpdatedTimes: []*health.DateTimeRange{
					{},
				},
			},
			eventAPIResponses: []*health.DescribeEventsOutput{
				{
					Events: []*health.Event{
						{
							Arn: aws.String("arn1"),
						},
					},
					NextToken: nil,
				},
			},
			detailInput: [][]*string{
				{aws.String("arn1")},
			},
			detailAPIResponses: []*health.DescribeEventDetailsOutput{
				{
					SuccessfulSet: []*health.EventDetails{
						{
							Event: &health.Event{
								Arn:             aws.String("arn1"),
								Region:          aws.String("region"),
								EventTypeCode:   aws.String("EVENT_CODE"),
								LastUpdatedTime: &time.Time{},
								StatusCode:      aws.String("status"),
							},
							EventDescription: &health.EventDescription{
								LatestDescription: aws.String("description"),
							},
						},
					},
				},
			},
			entityInputArn: [][]*string{
				{aws.String("arn1")},
			},
			entityInputToken: []*string{nil, aws.String("a token")},
			entityAPIResponses: []*health.DescribeAffectedEntitiesOutput{
				{
					Entities: []*health.AffectedEntity{
						{
							EntityValue: aws.String("entity value1"),
							EventArn:    aws.String("arn1"),
						},
					},
					NextToken: nil,
				},
			},
			expectedError: nil,
			expectedOutput: []healthReportFinding{
				{
					AccountID:        "account",
					AffectedEntities: []string{"entity value1"},
					Arn:              "arn1",
					Comments:         "NEW_FINDING",
					EventTypeCode:    "Event Code",
					LastUpdatedTime:  "0001-01-01 00:00:00 +0000 UTC",
					Region:           "region",
					StatusCode:       "status",
					EventDescription: "description",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			// loop through checks and simulate calling method and returning corresponding responses
			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			mockAPIs.EXPECT().GetAccountID().Return("account", nil).MaxTimes(1)
			for i := 0; i < len(tc.eventInput); i++ {
				mockAPIs.EXPECT().GetHealthEvents(tc.eventFilter, tc.eventInput[i]).Return(tc.eventAPIResponses[i], tc.expectedError).MaxTimes(len(tc.eventInput))
				mockAPIs.EXPECT().GetHealthEventDetails(tc.detailInput[i]).Return(tc.detailAPIResponses[i], tc.expectedError).MaxTimes(len(tc.detailInput))
				mockAPIs.EXPECT().GetHealthAffectedEntities(tc.entityInputArn[i], tc.entityInputToken[i]).Return(tc.entityAPIResponses[i], tc.expectedError).MaxTimes(len(tc.entityInputToken))
			}

			comments := parseCommentsFile("../../test/data/comments.yaml")
			report := &HealthReport{
				Flags: healthReportFlags{
					Details:  false,
					PastDays: "",
				},
			}
			err := report.GetReport(mockAPIs, comments)

			assert.Equal(t, tc.expectedOutput, report.Findings)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestCreateArnArray(t *testing.T) {
	testCases := []struct {
		name           string
		input          []*string
		eventFilter    *health.EventFilter
		apiResponses   []*health.DescribeEventsOutput
		expectedOutput []*string
		expectedError  error
	}{
		{
			name:  "Return Events with a next token one time",
			input: []*string{nil, aws.String("a token")},
			eventFilter: &health.EventFilter{
				EventTypeCategories: []*string{aws.String("accountNotification")},
				EventStatusCodes:    []*string{aws.String("open"), aws.String("upcoming")},
				LastUpdatedTimes: []*health.DateTimeRange{
					{},
				},
			},
			apiResponses: []*health.DescribeEventsOutput{
				{
					Events: []*health.Event{
						{
							Arn: aws.String("arn1"),
						},
					},
					NextToken: aws.String("a token"),
				},
				{
					Events: []*health.Event{
						{
							Arn: aws.String("arn2"),
						},
					},
					NextToken: nil,
				},
			},
			expectedOutput: []*string{aws.String("arn1"), aws.String("arn2")},
			expectedError:  nil,
		},
		{
			name:  "Return error",
			input: []*string{nil},
			eventFilter: &health.EventFilter{
				EventTypeCategories: []*string{aws.String("accountNotification")},
				EventStatusCodes:    []*string{aws.String("open"), aws.String("upcoming")},
				LastUpdatedTimes: []*health.DateTimeRange{
					{},
				},
			},
			apiResponses: []*health.DescribeEventsOutput{
				nil,
			},
			expectedOutput: nil,
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			// loop through checks and simulate calling method and returning corresponding responses
			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			for i := 0; i < len(tc.input); i++ {
				mockAPIs.EXPECT().GetHealthEvents(tc.eventFilter, tc.input[i]).Return(tc.apiResponses[i], tc.expectedError).MaxTimes(len(tc.input))
			}

			output, err := createArnArray(mockAPIs, healthReportFlags{})
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestGetAllEventDetails(t *testing.T) {
	testCases := []struct {
		name           string
		input          [][]*string
		apiResponses   []*health.DescribeEventDetailsOutput
		expectedOutput *health.DescribeEventDetailsOutput
		expectedError  error
	}{
		{
			name: "Return Events Details with only successful sets",
			input: [][]*string{
				{aws.String("arn1")},
				{aws.String("arn2")},
			},
			apiResponses: []*health.DescribeEventDetailsOutput{
				{
					SuccessfulSet: []*health.EventDetails{
						{
							Event: &health.Event{
								Arn: aws.String("arn1"),
							},
						},
					},
				},
				{
					SuccessfulSet: []*health.EventDetails{
						{
							Event: &health.Event{
								Arn: aws.String("arn2"),
							},
						},
					},
				},
			},
			expectedOutput: &health.DescribeEventDetailsOutput{
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
				FailedSet: []*health.EventDetailsErrorItem{},
			},
			expectedError: nil,
		},
		{
			name: "Return Events Details with a failed set",
			input: [][]*string{
				{aws.String("arn1")},
				{aws.String("arn2")},
			},
			apiResponses: []*health.DescribeEventDetailsOutput{
				{
					FailedSet: []*health.EventDetailsErrorItem{
						{
							EventArn: aws.String("arn1"),
						},
					},
				},
				{
					FailedSet: []*health.EventDetailsErrorItem{
						{
							EventArn: aws.String("arn2"),
						},
					},
				},
			},
			expectedOutput: &health.DescribeEventDetailsOutput{
				SuccessfulSet: []*health.EventDetails{},
				FailedSet: []*health.EventDetailsErrorItem{
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
			name: "Return error",
			input: [][]*string{
				{aws.String("arn1")},
			},
			apiResponses: []*health.DescribeEventDetailsOutput{
				nil,
			},
			expectedOutput: nil,
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			// loop through checks and simulate calling method and returning corresponding responses
			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			for i := 0; i < len(tc.input); i++ {
				mockAPIs.EXPECT().GetHealthEventDetails(tc.input[i]).Return(tc.apiResponses[i], tc.expectedError).MaxTimes(len(tc.input))
			}

			output, err := getAllEventDetails(mockAPIs, []*string{aws.String("arn1"), aws.String("arn2")}, 1)
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestGetAllAffectedEntities(t *testing.T) {
	testCases := []struct {
		name           string
		inputArn       [][]*string
		inputToken     []*string
		apiResponses   []*health.DescribeAffectedEntitiesOutput
		expectedOutput map[string][]string
		expectedError  error
	}{
		{
			name: "Return Affected entities",
			inputArn: [][]*string{
				{aws.String("arn1"), aws.String("arn2")},
				{aws.String("arn1"), aws.String("arn2")},
			},
			inputToken: []*string{nil, aws.String("a token")},
			apiResponses: []*health.DescribeAffectedEntitiesOutput{
				{
					Entities: []*health.AffectedEntity{
						{
							EntityValue: aws.String("entity value1"),
							EventArn:    aws.String("arn1"),
						},
					},
					NextToken: aws.String("a token"),
				},
				{
					Entities: []*health.AffectedEntity{
						{
							EntityValue: aws.String("entity value2"),
							EventArn:    aws.String("arn2"),
						},
					},
					NextToken: nil,
				},
			},
			expectedOutput: map[string][]string{
				"arn1": {"entity value1"},
				"arn2": {"entity value2"},
			},
			expectedError: nil,
		},
		{
			name: "Return error",
			inputArn: [][]*string{
				{aws.String("arn1"), aws.String("arn2")},
			},
			inputToken: []*string{nil},
			apiResponses: []*health.DescribeAffectedEntitiesOutput{
				nil,
			},
			expectedOutput: nil,
			expectedError:  errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			// loop through checks and simulate calling method and returning corresponding responses
			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			for i := 0; i < len(tc.inputToken); i++ {
				mockAPIs.EXPECT().GetHealthAffectedEntities(tc.inputArn[i], tc.inputToken[i]).Return(tc.apiResponses[i], tc.expectedError).MaxTimes(len(tc.inputToken))
			}

			output, err := getAllAffectedEntities(mockAPIs, []*string{aws.String("arn1"), aws.String("arn2")}, 2)
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestScrubEventTypeCode(t *testing.T) {
	output := scrubEventTypeCode("AWS_STRING_ONE_TWO_THREE")
	assert.Equal(t, "String One Two Three", output)
	output = scrubEventTypeCode("STRING_ONE_TWO_THREE")
	assert.Equal(t, "String One Two Three", output)
}

func TestScrubEventDescription(t *testing.T) {
	output, _ := scrubEventDescription("One.\n\r Two.\n Three.\r Four.", true)
	assert.Equal(t, "One. Two. Three. Four.", output)
	output, _ = scrubEventDescription("One.\n\r Two.\n Three.\r Four.", false)
	assert.Equal(t, "One. Two. Three.", output)
}
