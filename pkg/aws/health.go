package aws

import (
	"errors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/health"
)

// HealthSVC is a wrapper for Support API calls related to Health Notifactions
type HealthSVC interface {
	GetHealthEvents(eventFilter *health.EventFilter, nextToken *string) (*health.DescribeEventsOutput, error)
	GetHealthEventDetails(arnArr []*string) (*health.DescribeEventDetailsOutput, error)
	GetHealthAffectedEntities(arnArr []*string, nextToken *string) (*health.DescribeAffectedEntitiesOutput, error)
}

// GetHealthEvents returns a list of Health notification events
func (client *Client) GetHealthEvents(eventFilter *health.EventFilter, nextToken *string) (*health.DescribeEventsOutput, error) {
	if eventFilter == nil {
		eventFilter = &health.EventFilter{
			EventTypeCategories: []*string{aws.String("accountNotification")},
			EventStatusCodes:    []*string{aws.String("open"), aws.String("upcoming")},
		}
	}
	result, err := client.Health.DescribeEvents(&health.DescribeEventsInput{
		Filter:     eventFilter,
		MaxResults: aws.Int64(100), // Max event results per api is 100
		NextToken:  nextToken,
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetHealthEventDetails returns a list of Health notification events
func (client *Client) GetHealthEventDetails(arnArr []*string) (*health.DescribeEventDetailsOutput, error) {
	if arnArr == nil || len(arnArr) == 0 || len(arnArr) > 10 {
		return nil, errors.New("Describe event details can only query for 1-10 event details at a time")
	}
	result, err := client.Health.DescribeEventDetails(&health.DescribeEventDetailsInput{
		EventArns: arnArr,
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetHealthAffectedEntities returns a list of Health notification events
func (client *Client) GetHealthAffectedEntities(arnArr []*string, nextToken *string) (*health.DescribeAffectedEntitiesOutput, error) {
	if arnArr == nil || len(arnArr) == 0 || len(arnArr) > 100 {
		return nil, errors.New("Describe affected entities can only query for 1-100 event details at a time")
	}
	result, err := client.Health.DescribeAffectedEntities(&health.DescribeAffectedEntitiesInput{
		Filter: &health.EntityFilter{
			EventArns: arnArr,
		},
		NextToken: nextToken,
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}
