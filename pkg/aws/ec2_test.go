package aws

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetInstances(t *testing.T) {
	testCases := []struct {
		name          string
		output        *ec2.DescribeInstancesOutput
		expectedError error
	}{
		{
			name:          "Empty response",
			output:        &ec2.DescribeInstancesOutput{},
			expectedError: nil,
		},
		{
			name: "Populated response",
			output: &ec2.DescribeInstancesOutput{Reservations: []*ec2.Reservation{
				{
					Instances: []*ec2.Instance{
						{
							ImageId:    aws.String("TEST_AMI"),
							InstanceId: aws.String("i-00000test000000000"),
							Platform:   aws.String("Linux"),
							IamInstanceProfile: &ec2.IamInstanceProfile{
								Arn: aws.String("arn:aws:iam::111111111111:instance-profile/test-profile"),
								Id:  aws.String("AIPAJO5KIRR7I5NITEST"),
							},
						},
					},
					OwnerId:       aws.String("111111111111"),
					RequesterId:   aws.String("940372691376"),
					ReservationId: aws.String("r-testf4fe629c3test"),
				},
				{
					Instances: []*ec2.Instance{
						{
							ImageId:    aws.String("TEST_AMI-2"),
							InstanceId: aws.String("i-00000test000001111"),
							Platform:   aws.String("Linux2"),
							IamInstanceProfile: &ec2.IamInstanceProfile{
								Arn: aws.String("arn:aws:iam::111111111111:instance-profile/test-profile-1"),
								Id:  aws.String("AIPAJO5KIRR7I5NITEST1"),
							},
						},
					},
					OwnerId:       aws.String("111111111111"),
					RequesterId:   aws.String("940372691376"),
					ReservationId: aws.String("r-testf4fe629ctest1"),
				},
			}},
			expectedError: nil,
		},
		{
			name:          "Error response",
			output:        nil,
			expectedError: errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockEC2API := mocks.NewMockEC2API(mockCtrl)
			mockEC2API.EXPECT().DescribeInstances(&ec2.DescribeInstancesInput{}).Return(tc.output, tc.expectedError)
			client := &Client{
				EC2: mockEC2API,
			}

			output, err := client.GetInstances()
			assert.Equal(t, tc.output, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestGetInstancesByFilters(t *testing.T) {
	testCases := []struct {
		name          string
		input         map[string][]string
		output        *ec2.DescribeInstancesOutput
		expectedError error
	}{
		{
			name: "Empty response",
			input: map[string][]string{
				"availability-zone": {"us-east-1a", "us-east-1b"},
			},
			output:        &ec2.DescribeInstancesOutput{},
			expectedError: nil,
		},
		{
			name: "Populated response",
			input: map[string][]string{
				"availability-zone": {"us-east-1a", "us-east-1b"},
				"instance-type":     {"m5.large"},
			},
			output: &ec2.DescribeInstancesOutput{Reservations: []*ec2.Reservation{
				{
					Instances: []*ec2.Instance{
						{
							ImageId:      aws.String("TEST_AMI"),
							InstanceId:   aws.String("i-00000test000000000"),
							InstanceType: aws.String("m5.large"),
							Placement: &ec2.Placement{
								AvailabilityZone: aws.String("us-east-1a"),
							},
						},
					},
					OwnerId:       aws.String("111111111111"),
					RequesterId:   aws.String("940372691376"),
					ReservationId: aws.String("r-testf4fe629c3test"),
				},
				{
					Instances: []*ec2.Instance{
						{
							ImageId:      aws.String("TEST_AMI-2"),
							InstanceId:   aws.String("i-00000test000001111"),
							InstanceType: aws.String("m5.large"),
							Placement: &ec2.Placement{
								AvailabilityZone: aws.String("us-east-1b"),
							},
						},
					},
					OwnerId:       aws.String("111111111111"),
					RequesterId:   aws.String("940372691376"),
					ReservationId: aws.String("r-testf4fe629ctest1"),
				},
			}},
			expectedError: nil,
		},
		{
			name: "Error response",

			input: map[string][]string{
				"instance-type": {"m5.large"},
			},
			output:        nil,
			expectedError: errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockEC2API := mocks.NewMockEC2API(mockCtrl)

			// Build list of filters
			ec2FiltersList := []*ec2.Filter{}
			// Maps, when indexed with range, might not always output in the right order
			// Thus to fix this test, we can add a second input check with the reversed filters
			// As there exists only 2 filters, this covers all possible orderings
			ec2FiltersList2 := []*ec2.Filter{}
			for name, values := range tc.input {
				ec2FiltersList = append(ec2FiltersList, &ec2.Filter{Name: aws.String(name), Values: aws.StringSlice(values)})
			}
			for i := (len(ec2FiltersList) - 1); i >= 0; i-- {
				ec2FiltersList2 = append(ec2FiltersList2, ec2FiltersList[i])
			}

			mockEC2API.EXPECT().DescribeInstances(&ec2.DescribeInstancesInput{Filters: ec2FiltersList}).Return(tc.output, tc.expectedError).MaxTimes(1)
			mockEC2API.EXPECT().DescribeInstances(&ec2.DescribeInstancesInput{Filters: ec2FiltersList2}).Return(tc.output, tc.expectedError).MaxTimes(1)
			client := &Client{
				EC2: mockEC2API,
			}

			output, err := client.GetInstancesByFilters(tc.input)
			assert.Equal(t, tc.output, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestGetInstancesMatchingAnyTags(t *testing.T) {
	type input struct {
		tags map[string]string
	}
	testCases := []struct {
		name                     string
		input                    input
		describeInstancesOutputs []*ec2.DescribeInstancesOutput
		expectedOutput           *ec2.DescribeInstancesOutput
		expectedError            error
	}{
		{
			name: "Return correct result",
			input: input{
				tags: map[string]string{
					"aws_inspector": "true",
					"terraform":     "true",
				},
			},
			describeInstancesOutputs: []*ec2.DescribeInstancesOutput{
				{
					Reservations: []*ec2.Reservation{
						{
							Instances: []*ec2.Instance{
								{
									ImageId:      aws.String("TEST_AMI"),
									InstanceId:   aws.String("i-00000test000000000"),
									InstanceType: aws.String("m5.2xlarge"),
									Tags: []*ec2.Tag{
										{
											Key:   aws.String("aws_inspector"),
											Value: aws.String("true"),
										},
									},
								},
							},
							OwnerId:       aws.String("111111111111"),
							RequesterId:   aws.String("940372691376"),
							ReservationId: aws.String("r-testf4fe629c3test"),
						},
					},
				},
				{
					Reservations: []*ec2.Reservation{
						{
							Instances: []*ec2.Instance{
								{
									ImageId:      aws.String("TEST_AMI"),
									InstanceId:   aws.String("i-00000test0000001111"),
									InstanceType: aws.String("m5.2xlarge"),
									Tags: []*ec2.Tag{

										{
											Key:   aws.String("terraform"),
											Value: aws.String("true"),
										},
									},
								},
								{
									ImageId:      aws.String("TEST_AMI-2"),
									InstanceId:   aws.String("i-00000test000002222"),
									InstanceType: aws.String("m5.xlarge"),
									Tags: []*ec2.Tag{
										{
											Key:   aws.String("terraform"),
											Value: aws.String("true"),
										},
									},
								},
							},
							OwnerId:       aws.String("111111111111"),
							RequesterId:   aws.String("940372691376"),
							ReservationId: aws.String("r-testf4fe629c3test1"),
						},
					},
				},
			},
			expectedOutput: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								ImageId:      aws.String("TEST_AMI"),
								InstanceId:   aws.String("i-00000test000000000"),
								InstanceType: aws.String("m5.2xlarge"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("aws_inspector"),
										Value: aws.String("true"),
									},
								},
							},
						},
						OwnerId:       aws.String("111111111111"),
						RequesterId:   aws.String("940372691376"),
						ReservationId: aws.String("r-testf4fe629c3test"),
					},
					{
						Instances: []*ec2.Instance{
							{
								ImageId:      aws.String("TEST_AMI"),
								InstanceId:   aws.String("i-00000test0000001111"),
								InstanceType: aws.String("m5.2xlarge"),
								Tags: []*ec2.Tag{

									{
										Key:   aws.String("terraform"),
										Value: aws.String("true"),
									},
								},
							},
							{
								ImageId:      aws.String("TEST_AMI-2"),
								InstanceId:   aws.String("i-00000test000002222"),
								InstanceType: aws.String("m5.xlarge"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("terraform"),
										Value: aws.String("true"),
									},
								},
							},
						},
						OwnerId:       aws.String("111111111111"),
						RequesterId:   aws.String("940372691376"),
						ReservationId: aws.String("r-testf4fe629c3test1"),
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "Return correct result if a reservation has an instance with different tags that do not match other instances",
			input: input{
				tags: map[string]string{
					"aws_inspector": "true",
					"terraform":     "true",
				},
			},
			describeInstancesOutputs: []*ec2.DescribeInstancesOutput{
				{
					Reservations: []*ec2.Reservation{
						{
							Instances: []*ec2.Instance{
								{
									ImageId:      aws.String("TEST_AMI"),
									InstanceId:   aws.String("i-00000test000000000"),
									InstanceType: aws.String("m5.2xlarge"),
									Tags: []*ec2.Tag{
										{
											Key:   aws.String("aws_inspector"),
											Value: aws.String("true"),
										},
										{
											Key:   aws.String("terraform"),
											Value: aws.String("true"),
										},
									},
								},
							},
							OwnerId:       aws.String("111111111111"),
							RequesterId:   aws.String("940372691376"),
							ReservationId: aws.String("r-testf4fe629c3test"),
						},
					},
				},
				{
					Reservations: []*ec2.Reservation{
						{
							Instances: []*ec2.Instance{
								{
									ImageId:      aws.String("TEST_AMI-2"),
									InstanceId:   aws.String("i-00000test000001111"),
									InstanceType: aws.String("m5.xlarge"),
									Tags: []*ec2.Tag{
										{
											Key:   aws.String("terraform"),
											Value: aws.String("true"),
										},
									},
								},
								{
									ImageId:      aws.String("TEST_AMI"),
									InstanceId:   aws.String("i-00000test000000000"),
									InstanceType: aws.String("m5.2xlarge"),
									Tags: []*ec2.Tag{
										{
											Key:   aws.String("aws_inspector"),
											Value: aws.String("true"),
										},
										{
											Key:   aws.String("terraform"),
											Value: aws.String("true"),
										},
									},
								},
							},
							OwnerId:       aws.String("111111111111"),
							RequesterId:   aws.String("940372691376"),
							ReservationId: aws.String("r-testf4fe629c3test"),
						},
					},
				},
			},
			expectedOutput: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								ImageId:      aws.String("TEST_AMI"),
								InstanceId:   aws.String("i-00000test000000000"),
								InstanceType: aws.String("m5.2xlarge"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("aws_inspector"),
										Value: aws.String("true"),
									},
									{
										Key:   aws.String("terraform"),
										Value: aws.String("true"),
									},
								},
							},
							{
								ImageId:      aws.String("TEST_AMI-2"),
								InstanceId:   aws.String("i-00000test000001111"),
								InstanceType: aws.String("m5.xlarge"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("terraform"),
										Value: aws.String("true"),
									},
								},
							},
						},
						OwnerId:       aws.String("111111111111"),
						RequesterId:   aws.String("940372691376"),
						ReservationId: aws.String("r-testf4fe629c3test"),
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "Error response",
			input: input{
				tags: map[string]string{
					"aws_inspector": "true",
					"terraform":     "true",
				},
			},
			expectedError: errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockEC2API := mocks.NewMockEC2API(mockCtrl)

			ec2FiltersList := []*ec2.Filter{}
			for tag, value := range tc.input.tags {
				ec2FiltersList = append(ec2FiltersList, &ec2.Filter{Name: aws.String(fmt.Sprintf("tag:%s", tag)), Values: aws.StringSlice([]string{value})})
			}

			// Simulate calls made for each tag
			if len(tc.describeInstancesOutputs) > 0 {
				for i := range ec2FiltersList {
					mockEC2API.EXPECT().DescribeInstances(&ec2.DescribeInstancesInput{Filters: []*ec2.Filter{ec2FiltersList[i]}}).Return(tc.describeInstancesOutputs[i], tc.expectedError).MaxTimes(len(ec2FiltersList))
				}
			} else {
				// Error case
				mockEC2API.EXPECT().DescribeInstances(gomock.Any()).Return(tc.expectedOutput, tc.expectedError).MaxTimes(1)
			}

			client := &Client{
				EC2: mockEC2API,
			}

			// Sort output to match with expected output (only for non-error cases)
			// reflect.DeepEqual is not able to handle deeply nested slices of structs.
			// This causes an error as their order can change from run to run
			output, err := client.GetInstancesMatchingAnyTags(tc.input.tags)
			if len(tc.describeInstancesOutputs) > 0 {
				sort.SliceStable(output.Reservations, func(i, j int) bool {
					return *output.Reservations[i].ReservationId < *output.Reservations[j].ReservationId
				})

				for _, res := range output.Reservations {
					sort.SliceStable(res.Instances, func(i, j int) bool {
						return *res.Instances[i].InstanceId < *res.Instances[j].InstanceId
					})
				}
			}

			if !reflect.DeepEqual(tc.expectedOutput, output) {
				t.Errorf("Expected %v, got %v", tc.expectedOutput, output)
			}
			assert.Equal(t, tc.expectedError, err)
		})
	}
}
func TestGetInstancesMatchingAllTags(t *testing.T) {
	type input struct {
		tags map[string]string
	}
	testCases := []struct {
		name                    string
		input                   input
		describeInstancesOutput *ec2.DescribeInstancesOutput
		expectedOutput          *ec2.DescribeInstancesOutput
		expectedError           error
	}{
		{
			name: "Return correct result",
			input: input{
				tags: map[string]string{
					"aws_inspector": "true",
					"terraform":     "true",
				},
			},
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								ImageId:      aws.String("TEST_AMI"),
								InstanceId:   aws.String("i-00000test000000000"),
								InstanceType: aws.String("m5.2xlarge"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("aws_inspector"),
										Value: aws.String("true"),
									},
									{
										Key:   aws.String("terraform"),
										Value: aws.String("true"),
									},
								},
							},
						},
						OwnerId:       aws.String("111111111111"),
						RequesterId:   aws.String("940372691376"),
						ReservationId: aws.String("r-testf4fe629c3test"),
					},
					{
						Instances: []*ec2.Instance{
							{
								ImageId:      aws.String("TEST_AMI-2"),
								InstanceId:   aws.String("i-00000test000001111"),
								InstanceType: aws.String("m5.xlarge"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("aws_inspector"),
										Value: aws.String("true"),
									},
									{
										Key:   aws.String("terraform"),
										Value: aws.String("true"),
									},
								},
							},
						},
						OwnerId:       aws.String("111111111111"),
						RequesterId:   aws.String("940372691376"),
						ReservationId: aws.String("r-testf4fe629c3test1"),
					},
				},
			},
			expectedOutput: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								ImageId:      aws.String("TEST_AMI"),
								InstanceId:   aws.String("i-00000test000000000"),
								InstanceType: aws.String("m5.2xlarge"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("aws_inspector"),
										Value: aws.String("true"),
									},
									{
										Key:   aws.String("terraform"),
										Value: aws.String("true"),
									},
								},
							},
						},
						OwnerId:       aws.String("111111111111"),
						RequesterId:   aws.String("940372691376"),
						ReservationId: aws.String("r-testf4fe629c3test"),
					},
					{
						Instances: []*ec2.Instance{
							{
								ImageId:      aws.String("TEST_AMI-2"),
								InstanceId:   aws.String("i-00000test000001111"),
								InstanceType: aws.String("m5.xlarge"),
								Tags: []*ec2.Tag{
									{
										Key:   aws.String("aws_inspector"),
										Value: aws.String("true"),
									},
									{
										Key:   aws.String("terraform"),
										Value: aws.String("true"),
									},
								},
							},
						},
						OwnerId:       aws.String("111111111111"),
						RequesterId:   aws.String("940372691376"),
						ReservationId: aws.String("r-testf4fe629c3test1"),
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "Error response",
			input: input{
				tags: map[string]string{
					"aws_inspector": "true",
					"terraform":     "true",
				},
			},
			expectedError: errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockEC2API := mocks.NewMockEC2API(mockCtrl)

			// Maps, when indexed with range, might not always output in the right order
			// This will cause the expected input DescribeInstances to fail if the resulting map is in a different order than expected
			// To fix this, we will sort the ec2 filter
			ec2FiltersList := []*ec2.Filter{}
			for tag, value := range tc.input.tags {
				ec2FiltersList = append(ec2FiltersList, &ec2.Filter{Name: aws.String(fmt.Sprintf("tag:%s", tag)), Values: aws.StringSlice([]string{value})})
			}
			ec2FiltersList2 := []*ec2.Filter{}
			for i := (len(ec2FiltersList) - 1); i >= 0; i-- {
				ec2FiltersList2 = append(ec2FiltersList2, ec2FiltersList[i])
			}

			mockEC2API.EXPECT().DescribeInstances(&ec2.DescribeInstancesInput{Filters: ec2FiltersList}).Return(tc.describeInstancesOutput, tc.expectedError).MaxTimes(1)
			mockEC2API.EXPECT().DescribeInstances(&ec2.DescribeInstancesInput{Filters: ec2FiltersList2}).Return(tc.describeInstancesOutput, tc.expectedError).MaxTimes(1)

			client := &Client{
				EC2: mockEC2API,
			}

			output, err := client.GetInstancesMatchingAllTags(tc.input.tags)
			if !reflect.DeepEqual(tc.expectedOutput, output) {
				t.Errorf("Expected %v, got %v", tc.expectedOutput, output)
			}
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestGetImageInformation(t *testing.T) {
	testCases := []struct {
		name          string
		input         []string
		output        *ec2.DescribeImagesOutput
		expectedError error
	}{
		{
			name:          "Empty response",
			input:         []string{"TEST_AMI-1", "TEST_AMI-2"},
			output:        &ec2.DescribeImagesOutput{},
			expectedError: nil,
		},
		{
			name:  "Populated response",
			input: []string{"TEST_AMI-1", "TEST_AMI-2"},
			output: &ec2.DescribeImagesOutput{
				Images: []*ec2.Image{
					{
						ImageId: aws.String("TEST_AMI-1"),
					},
					{
						ImageId: aws.String("TEST_AMI-2"),
					},
				},
			},
			expectedError: nil,
		},
		{
			name:          "Error response",
			input:         []string{"TEST_AMI-1", "TEST_AMI-2"},
			output:        nil,
			expectedError: errors.New("Some API error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockEC2API := mocks.NewMockEC2API(mockCtrl)
			mockEC2API.EXPECT().DescribeImages(&ec2.DescribeImagesInput{ImageIds: aws.StringSlice(tc.input)}).Return(tc.output, tc.expectedError)
			client := &Client{
				EC2: mockEC2API,
			}

			output, err := client.GetImageInformation(tc.input)
			assert.Equal(t, tc.output, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}

}
