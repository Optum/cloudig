package cloudig

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"gopkg.in/neurosnap/sentences.v1/english"

	awslocal "github.com/Optum/cloudig/pkg/aws"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/health"
	"github.com/sirupsen/logrus"
)

// HealthReport is a struct that contains an array of healthReport
type HealthReport struct {
	Findings []healthReportFinding `json:"findings"`
	Flags    healthReportFlags     `json:"-"` // hide in json output
	jsonOutputHelper
}

type healthReportFlags struct {
	Details  bool
	PastDays string
}

type healthReportFinding struct {
	AccountID        string   `json:"accountId"`
	Arn              string   `json:"arn"`
	AffectedEntities []string `json:"affectedEntities"`
	Comments         string   `json:"comments"`
	EventTypeCode    string   `json:"eventTypeCode"`
	LastUpdatedTime  string   `json:"lastUpdatedTime"`
	Region           string   `json:"region"`
	StatusCode       string   `json:"statusCode"`
	EventDescription string   `json:"eventDescription"`
}

// GetReport builds the Inspector report for a given assessment run
func (report *HealthReport) GetReport(client awslocal.APIs, comments []Comments) error {
	start := time.Now()

	// Get accountID from roleARN
	accountID, err := client.GetAccountID()
	if err != nil {
		return err
	}
	logrus.Infof("working on AWS HealthReport for account: %s", accountID)

	logrus.Infof("finding all health events for account: %s", accountID)
	// get basic event info, and create arn array to then query specifically for detailed output
	arnArr, err := createArnArray(client, report.Flags)
	if err != nil {
		return err
	}
	// get all wanted available information from the Health Event(corresponding details and affected entities)
	eventDetails, err := getAllEventDetails(client, arnArr, 10)
	if err != nil {
		return err
	}

	logrus.Infof("finding affected entities for health events in account: %s", accountID)
	// a map is needed here to synchronize with eventdetails
	affectedEntities, err := getAllAffectedEntities(client, arnArr, 10)
	if err != nil {
		return err
	}

	if len(eventDetails.FailedSet) > 0 {
		return errors.New("One of the provided arns failed to provide details")
	}
	// parse to the format that wil be outputted
	for _, details := range eventDetails.SuccessfulSet {
		eventDes, err := scrubEventDescription(*details.EventDescription.LatestDescription, report.Flags.Details)
		if err != nil {
			return err
		}
		finding := healthReportFinding{
			AccountID:        accountID,
			AffectedEntities: affectedEntities[*details.Event.Arn],
			Arn:              *details.Event.Arn,
			Comments:         getComments(comments, accountID, findingTypeAWSHealth, *details.Event.EventTypeCode),
			EventTypeCode:    scrubEventTypeCode(*details.Event.EventTypeCode),
			LastUpdatedTime:  (*details.Event.LastUpdatedTime).String(),
			Region:           *details.Event.Region,
			StatusCode:       *details.Event.StatusCode,
			EventDescription: eventDes,
		}
		report.Findings = append(report.Findings, finding)
	}

	logrus.Infof("getting AWS HealthReport for account %s took %s", accountID, time.Since(start))
	return nil
}

func createArnArray(client awslocal.APIs, flags healthReportFlags) ([]*string, error) {
	eventsArray := make([]*health.Event, 0)
	// Process flags into the event filter as desired
	if flags.PastDays == "" {
		// create unused value to mark all events
		flags.PastDays = "0"
	}
	pastDays, err := strconv.Atoi(flags.PastDays)
	if err != nil {
		return nil, err
	}
	// No scenario someone would look in the future, but someone might confuse positive and negative here
	if pastDays < 0 {
		pastDays *= -1
	}

	eventFilter := &health.EventFilter{
		EventTypeCategories: []*string{aws.String("accountNotification")},
		EventStatusCodes:    []*string{aws.String("open"), aws.String("upcoming")},
		LastUpdatedTimes: []*health.DateTimeRange{
			{
				From: func() *time.Time {
					if pastDays != 0 {
						return aws.Time(time.Now().AddDate(0, 0, -pastDays))
					}
					return nil
				}(),
			},
		},
	}

	var nextToken *string
	for {
		events, err := client.GetHealthEvents(eventFilter, nextToken)
		if err != nil {
			return nil, err
		}
		for _, event := range events.Events {
			eventsArray = append(eventsArray, event)
		}
		if events.NextToken == nil {
			break
		}
		nextToken = events.NextToken
	}

	arnArr := make([]*string, len(eventsArray))
	for i, event := range eventsArray {
		arnArr[i] = event.Arn
	}

	return arnArr, nil
}

func getAllEventDetails(client awslocal.APIs, arnArr []*string, maxCallSize int) (*health.DescribeEventDetailsOutput, error) {
	eventDetailsSuccessArray := make([]*health.EventDetails, 0)
	eventDetailsErrorItemArray := make([]*health.EventDetailsErrorItem, 0)
	for i := 0; i < len(arnArr); i += maxCallSize {
		eventDetails, err := client.GetHealthEventDetails(arnArr[i:min(len(arnArr), i+maxCallSize)])
		if err != nil {
			return nil, err
		}
		for _, eventD := range eventDetails.SuccessfulSet {
			eventDetailsSuccessArray = append(eventDetailsSuccessArray, eventD)
		}
		for _, eventD := range eventDetails.FailedSet {
			eventDetailsErrorItemArray = append(eventDetailsErrorItemArray, eventD)
		}
	}

	// combine array of arrays of event details to one array
	eventDetails := health.DescribeEventDetailsOutput{
		SuccessfulSet: eventDetailsSuccessArray,
		FailedSet:     eventDetailsErrorItemArray,
	}
	return &eventDetails, nil
}

func getAllAffectedEntities(client awslocal.APIs, arnArr []*string, maxCallSize int) (map[string][]string, error) {
	eventArnToEntityValueMap := make(map[string][]string)
	// we may only call GetHealthAffectedEntities, and its underlying health method, DescribeAffectedEntities->EntityFilter, with an array of
	// a 10 strings, thus have to have the cap, the for loop, and have pagination option for the many possible entites returned for each call
	for i := 0; i < len(arnArr); i += maxCallSize {
		var nextToken *string
		for {
			affectedEntitiesOutput, err := client.GetHealthAffectedEntities(arnArr[i:min(len(arnArr), i+maxCallSize)], nextToken)
			if err != nil {
				return nil, err
			}
			for _, entity := range affectedEntitiesOutput.Entities {
				eventArnToEntityValueMap[*entity.EventArn] = append(eventArnToEntityValueMap[*entity.EventArn], *entity.EntityValue)
			}
			if affectedEntitiesOutput.NextToken == nil {
				break
			}
			nextToken = affectedEntitiesOutput.NextToken
		}
	}
	return eventArnToEntityValueMap, nil
}

func scrubEventTypeCode(name string) string {
	// Remove AWS_ as it is redundant, remove underscores, and capitalize normally
	parts := strings.Split(name, "_")
	if parts[0] == "AWS" {
		parts = parts[1:]
	}
	for i, part := range parts {
		parts[i] = strings.Title(strings.ToLower(part))
	}
	return strings.Join(parts, " ")
}

func scrubEventDescription(eventDesc string, details bool) (string, error) {
	// parse the string as the event description is printed as a raw string,
	// not rendered
	replacer := strings.NewReplacer(
		"\u003e", "",
		"\u0085", "",
		"\u2028", "",
		"\u2029", "",
		"\"", "'",
		"\r\n*", "",
		"\r\n\r\n", " ",
		"\r\n", " ",
		"\r", "",
		"\n", "",
		"\v", "",
		"\f", "",
	)

	proccessedDesc := replacer.Replace(eventDesc)
	if details {
		return proccessedDesc, nil
	}

	tokenizer, err := english.NewSentenceTokenizer(nil)
	if err != nil {
		return "", err
	}

	sentences := tokenizer.Tokenize(proccessedDesc)
	str := ""
	for i := 0; i < min(3, len(sentences)); i++ {
		str += sentences[i].Text
	}
	return str, nil
}
