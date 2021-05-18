package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// EC2SVC is a wrapper for EC2 API calls
type EC2SVC interface {
	GetInstances() (*ec2.DescribeInstancesOutput, error)
	GetImageInformation(imageIds []string) (*ec2.DescribeImagesOutput, error)
	GetInstancesMatchingAllTags(tags map[string]string) (*ec2.DescribeInstancesOutput, error)
	GetInstancesMatchingAnyTags(tags map[string]string) (*ec2.DescribeInstancesOutput, error)
	GetInstancesByFilters(ec2Filters map[string][]string) (*ec2.DescribeInstancesOutput, error)
}

// GetInstances returns a list of EC2 instances and information
func (client *Client) GetInstances() (*ec2.DescribeInstancesOutput, error) {
	result, err := client.EC2.DescribeInstances(&ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetImageInformation returns the information about a list of EC2 imageIds
func (client *Client) GetImageInformation(imageIds []string) (*ec2.DescribeImagesOutput, error) {
	output, err := client.EC2.DescribeImages(&ec2.DescribeImagesInput{ImageIds: aws.StringSlice(imageIds)})
	if err != nil {
		return nil, err
	}

	return output, nil
}

// GetInstancesMatchingAnyTags returns instances that match ANY tags and their respective values in a given list.
// Ex: "k8s.io/cluster-autoscaler/enabled": "true" AND/OR "terraform": "true"
func (client *Client) GetInstancesMatchingAnyTags(tags map[string]string) (*ec2.DescribeInstancesOutput, error) {
	result := &ec2.DescribeInstancesOutput{}
	for tag, value := range tags {
		response, err := client.GetInstancesByFilters(map[string][]string{fmt.Sprintf("tag:%s", tag): {value}})
		if err != nil {
			return nil, err
		}

		/* Processing logic
		1. Add reservation if not in existing list
		2. Else check if any instances for a given reservation were not existing list.
			* This could mean that the tags for a given instance were changed or updated since being launched
		*/

		if len(result.Reservations) > 0 {
			for _, reservation := range response.Reservations {
				newReservation := false
				for _, existingReservation := range result.Reservations {
					if *existingReservation.ReservationId != *reservation.ReservationId {
						newReservation = true
					} else {
						newReservation = false

						// Compare instances
						for _, instance := range reservation.Instances {
							newInstance := false
							for _, existingInstance := range existingReservation.Instances {
								if *existingInstance.InstanceId == *instance.InstanceId {
									newInstance = false
									break
								} else {
									newInstance = true
								}
							}
							if newInstance {
								existingReservation.Instances = append(existingReservation.Instances, instance)
							}
						}
						break
					}
				}

				if newReservation {
					result.Reservations = append(result.Reservations, reservation)
				}
			}
		} else {
			result.Reservations = append(result.Reservations, response.Reservations...)
		}

	}

	return result, nil
}

// GetInstancesMatchingAllTags returns instances that match ALL tags and their respective values in a given list.
// Ex: "k8s.io/cluster-autoscaler/enabled": "true" AND "terraform": "true"
func (client *Client) GetInstancesMatchingAllTags(tags map[string]string) (*ec2.DescribeInstancesOutput, error) {
	ec2Filters := make(map[string][]string, len(tags))
	for tag, value := range tags {
		ec2Filters[fmt.Sprintf("tag:%s", tag)] = []string{value}
	}

	return client.GetInstancesByFilters(ec2Filters)
}

// GetInstancesByFilters returns all instances that match a list of EC2 filters
func (client *Client) GetInstancesByFilters(ec2Filters map[string][]string) (*ec2.DescribeInstancesOutput, error) {
	// build list of filters
	ec2FiltersList := []*ec2.Filter{}
	for name, values := range ec2Filters {
		ec2FiltersList = append(ec2FiltersList, &ec2.Filter{Name: aws.String(name), Values: aws.StringSlice(values)})
	}

	output, err := client.EC2.DescribeInstances(&ec2.DescribeInstancesInput{Filters: ec2FiltersList})
	if err != nil {
		return nil, err
	}

	return output, nil
}
