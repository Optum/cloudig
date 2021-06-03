package cloudig

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// fakeInspectorHelper is used to fake downloading a report in TestInspectorGetReport
type fakeInspectorHelper struct{}

func (fakeHelper *fakeInspectorHelper) downloadReport(reportURL string, report inspectorReport) (string, error) {
	// Create copy of test inspector report for testing so original isn't deleted
	reportFile := "/tmp/inspector_report_" + report.AccountID + ".html"
	err := copy("../../test/data/inspector_report_test.html", reportFile)
	if err != nil {
		log.Fatalf("Error copying file: %s\n", err)
	}
	return reportFile, nil
}

func TestInspectorGetReport(t *testing.T) {
	logrus.SetOutput(ioutil.Discard)
	testCases := []struct {
		name                                        string
		accountID                                   string
		assessmentRunInfo                           []map[string]string
		resourceGroupTags                           map[string]string
		instancesList                               *ec2.DescribeInstancesOutput
		imageInformation                            *ec2.DescribeImagesOutput
		expectedReports                             []inspectorReport
		expectedGetAccountIDError                   error
		expectedGetMostRecentAssessmentRunInfoError error
		expectedGenerateReportError                 error
		expectedGetInstancesMatchingAnyTagsError    error
		expectedGetResourceGroupTagsError           error
		expectedGetImageInformationError            error
		expectedError                               error
	}{
		{
			name:      "Return expected report",
			accountID: "111111111111",
			assessmentRunInfo: []map[string]string{
				{
					"templateName": "test-once-dev",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW/template/0-qLRbgV2x/run/0-gKfIrDIK",
				},
				{
					"templateName": "k8s_weekly_scan",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF/template/0-eLtPoQf3/run/0-8Wf02Drc",
				},
			},
			resourceGroupTags: map[string]string{
				"dig-owned":     "True",
				"aws_inspector": "true",
				"terraform":     "True",
			},
			instancesList: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								ImageId: aws.String("ami-123"),
							},
							{
								ImageId: aws.String("ami-777"),
							},
						},
					},
					{
						Instances: []*ec2.Instance{
							{
								ImageId: aws.String("ami-777"),
							},
						},
					},
				},
			},
			imageInformation: &ec2.DescribeImagesOutput{
				Images: []*ec2.Image{
					{
						Name:         aws.String("TEST_AMI"),
						ImageId:      aws.String("ami-123"),
						CreationDate: aws.String("2019-11-03T05:57:38.000Z"),
					},
					{
						Name:         aws.String("TEST_AMI_2"),
						ImageId:      aws.String("ami-777"),
						CreationDate: aws.String("2019-12-08T05:57:38.000Z"),
					},
				},
			},
			expectedReports: []inspectorReport{
				{
					AccountID:    "111111111111",
					TemplateName: "test-once-dev",
					Findings: []inspectorReportFinding{
						{
							RulePackageName: "CIS Operating System Security Configuration Benchmarks-1.0",
							High:            "2581",
							Medium:          "0",
							Low:             "0",
							Informational:   "232",
							Comments:        "**EXCEPTION:** Description here",
						},
						{
							RulePackageName: "Common Vulnerabilities and Exposures-1.1",
							High:            "29",
							Medium:          "46",
							Low:             "0",
							Informational:   "0",
							Comments:        "NEW_FINDING",
						},
						{
							RulePackageName: "Runtime Behavior Analysis-1.0",
							High:            "0",
							Medium:          "0",
							Low:             "23",
							Informational:   "44",
							Comments:        "NEW_FINDING",
						},
						{
							RulePackageName: "Security Best Practices-1.0",
							High:            "0",
							Medium:          "0",
							Low:             "0",
							Informational:   "0",
							Comments:        "",
						},
					},
					AMI: map[string]int{
						"TEST_AMI":   getAgeInDays("2019-11-03T05:57:38.000Z"),
						"TEST_AMI_2": getAgeInDays("2019-12-08T05:57:38.000Z"),
					},
				},
				{
					AccountID:    "111111111111",
					TemplateName: "k8s_weekly_scan",
					Findings: []inspectorReportFinding{
						{
							RulePackageName: "CIS Operating System Security Configuration Benchmarks-1.0",
							High:            "2581",
							Medium:          "0",
							Low:             "0",
							Informational:   "232",
							Comments:        "**EXCEPTION:** Description here",
						},
						{
							RulePackageName: "Common Vulnerabilities and Exposures-1.1",
							High:            "29",
							Medium:          "46",
							Low:             "0",
							Informational:   "0",
							Comments:        "NEW_FINDING",
						},
						{
							RulePackageName: "Runtime Behavior Analysis-1.0",
							High:            "0",
							Medium:          "0",
							Low:             "23",
							Informational:   "44",
							Comments:        "NEW_FINDING",
						},
						{
							RulePackageName: "Security Best Practices-1.0",
							High:            "0",
							Medium:          "0",
							Low:             "0",
							Informational:   "0",
							Comments:        "",
						},
					},
					AMI: map[string]int{
						"TEST_AMI":   getAgeInDays("2019-11-03T05:57:38.000Z"),
						"TEST_AMI_2": getAgeInDays("2019-12-08T05:57:38.000Z"),
					},
				},
			},
			expectedError: nil,
		},
		{

			name:                      "Return error when getting AccountID",
			accountID:                 "",
			instancesList:             &ec2.DescribeInstancesOutput{},
			imageInformation:          &ec2.DescribeImagesOutput{},
			expectedGetAccountIDError: errors.New("Some API error"),
			expectedError:             errors.New("Some API error"),
		},
		{
			name:      "Return error when getting most recent Assement Run ARN",
			accountID: "111111111111",
			assessmentRunInfo: []map[string]string{
				{
					"templateName": "test-once-dev",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW/template/0-qLRbgV2x/run/0-gKfIrDIK",
				},
				{
					"templateName": "k8s_weekly_scan",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF/template/0-eLtPoQf3/run/0-8Wf02Drc",
				},
			},
			instancesList:    &ec2.DescribeInstancesOutput{},
			imageInformation: &ec2.DescribeImagesOutput{},
			expectedGetMostRecentAssessmentRunInfoError: errors.New("Some API error"),
			expectedError: errors.New("Some API error"),
		},
		{
			name:      "Return error when generating report",
			accountID: "111111111111",
			assessmentRunInfo: []map[string]string{
				{
					"templateName": "test-once-dev",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW/template/0-qLRbgV2x/run/0-gKfIrDIK",
				},
				{
					"templateName": "k8s_weekly_scan",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF/template/0-eLtPoQf3/run/0-8Wf02Drc",
				},
			},
			instancesList:               &ec2.DescribeInstancesOutput{},
			imageInformation:            &ec2.DescribeImagesOutput{},
			expectedGenerateReportError: errors.New("Some API error"),
			expectedError:               errors.New("Some API error"),
		},
		{
			name:      "Return error when getting list of AMIs and their ages",
			accountID: "111111111111",
			assessmentRunInfo: []map[string]string{
				{
					"templateName": "test-once-dev",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-4S2UxUbW/template/0-qLRbgV2x/run/0-gKfIrDIK",
				},
				{
					"templateName": "k8s_weekly_scan",
					"targetArn":    "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF",
					"arn":          "arn:aws:inspector:us-east-1:111111111111:target/0-E70Tx7xF/template/0-eLtPoQf3/run/0-8Wf02Drc",
				},
			},
			instancesList:                            &ec2.DescribeInstancesOutput{},
			imageInformation:                         &ec2.DescribeImagesOutput{},
			expectedGetInstancesMatchingAnyTagsError: errors.New("Some API error"),
			expectedGetImageInformationError:         errors.New("Some API error"),
			expectedError:                            errors.New("Some API error"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			mockAPIs.EXPECT().GetAccountID().Return(tc.accountID, tc.expectedGetAccountIDError).MaxTimes(1)
			mockAPIs.EXPECT().GetMostRecentAssessmentRunInfo().Return(tc.assessmentRunInfo, tc.expectedGetMostRecentAssessmentRunInfoError).MaxTimes(1)
			// We don't care about the reportURL returned by GenerateReport since we are using a local test report for getting findings
			for _, run := range tc.assessmentRunInfo {
				mockAPIs.EXPECT().GenerateReport(run["arn"], "HTML", "FULL").Return("", tc.expectedGenerateReportError).MaxTimes(len(tc.assessmentRunInfo))
				mockAPIs.EXPECT().GetResourceGroupTags(run["targetArn"]).Return(tc.resourceGroupTags, tc.expectedGetResourceGroupTagsError).MaxTimes(len(tc.assessmentRunInfo))
				mockAPIs.EXPECT().GetInstancesMatchingAnyTags(tc.resourceGroupTags).Return(tc.instancesList, tc.expectedGetInstancesMatchingAnyTagsError).MaxTimes(len(tc.assessmentRunInfo))
				mockAPIs.EXPECT().GetImageInformation(unique(getAmiList(tc.instancesList))).Return(tc.imageInformation, tc.expectedGetImageInformationError).MaxTimes(len(tc.assessmentRunInfo))
			}
			reports := &InspectorReports{Helper: &fakeInspectorHelper{}}

			// Use fakeInspectorReport's downloadReport method
			comments := parseCommentsFile("../../test/data/comments.yaml")

			err := reports.GetReport(mockAPIs, comments)
			assert.Equal(t, tc.expectedReports, reports.Reports)
			assert.Equal(t, tc.expectedError, err)
		})
	}
}

func TestGetAssessmentRunAgentAMIAndAge(t *testing.T) {
	logrus.SetOutput(ioutil.Discard)
	testCases := []struct {
		name                                     string
		resourceGroupTags                        map[string]string
		instancesList                            *ec2.DescribeInstancesOutput
		imageInformation                         *ec2.DescribeImagesOutput
		expectedGetResourceGroupTagsError        error
		expectedGetInstancesMatchingAnyTagsError error
		expectedGetImageInformationError         error
		expectedOutput                           map[string]int
		expectedError                            error
	}{
		{
			name: "Return correct map of AMIs and ages",
			resourceGroupTags: map[string]string{
				"dig-owned":     "True",
				"aws_inspector": "true",
				"terraform":     "True",
			},
			instancesList: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								ImageId: aws.String("ami-123"),
							},
							{
								ImageId: aws.String("ami-777"),
							},
						},
					},
					{
						Instances: []*ec2.Instance{
							{
								ImageId: aws.String("ami-777"),
							},
						},
					},
				},
			},
			imageInformation: &ec2.DescribeImagesOutput{
				Images: []*ec2.Image{
					{
						Name:         aws.String("TEST_AMI"),
						ImageId:      aws.String("ami-123"),
						CreationDate: aws.String("2019-11-03T05:57:38.000Z"),
					},
					{
						Name:         aws.String("TEST_AMI_2"),
						ImageId:      aws.String("ami-777"),
						CreationDate: aws.String("2019-12-08T05:57:38.000Z"),
					},
				},
			},
			expectedOutput: map[string]int{
				"TEST_AMI":   getAgeInDays("2019-11-03T05:57:38.000Z"),
				"TEST_AMI_2": getAgeInDays("2019-12-08T05:57:38.000Z"),
			},
			expectedError: nil,
		},
		{
			name:                              "Return error when calling GetResourceGroupTags",
			instancesList:                     &ec2.DescribeInstancesOutput{},
			imageInformation:                  &ec2.DescribeImagesOutput{},
			expectedGetResourceGroupTagsError: errors.New("Some API error"),
			expectedError:                     errors.New("Some API error"),
		},
		{
			name: "Return error when calling GetInstancesByTags",
			resourceGroupTags: map[string]string{
				"dig-owned":     "True",
				"aws_inspector": "true",
				"terraform":     "True",
			},
			instancesList:                            &ec2.DescribeInstancesOutput{},
			imageInformation:                         &ec2.DescribeImagesOutput{},
			expectedGetInstancesMatchingAnyTagsError: errors.New("Some API error"),
			expectedError:                            errors.New("Some API error"),
		},
		{
			name: "Return error when calling GetImageInformation",
			resourceGroupTags: map[string]string{
				"dig-owned":     "True",
				"aws_inspector": "true",
				"terraform":     "True",
			},
			instancesList: &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								ImageId: aws.String("ami-123"),
							},
							{
								ImageId: aws.String("ami-777"),
							},
						},
					},
					{
						Instances: []*ec2.Instance{
							{
								ImageId: aws.String("ami-777"),
							},
						},
					},
				},
			},
			imageInformation:                 &ec2.DescribeImagesOutput{},
			expectedGetImageInformationError: errors.New("Some API error"),
			expectedError:                    errors.New("Some API error"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockAPIs := mocks.NewMockAPIs(mockCtrl)
			mockAPIs.EXPECT().GetResourceGroupTags(gomock.Any()).Return(tc.resourceGroupTags, tc.expectedGetResourceGroupTagsError).MaxTimes(1)
			mockAPIs.EXPECT().GetInstancesMatchingAnyTags(tc.resourceGroupTags).Return(tc.instancesList, tc.expectedGetInstancesMatchingAnyTagsError).MaxTimes(1)
			mockAPIs.EXPECT().GetImageInformation(unique(getAmiList(tc.instancesList))).Return(tc.imageInformation, tc.expectedGetImageInformationError).MaxTimes(1)

			// We don't care about what is passed in for the targetArn for this test. We are testing what is returned
			output, err := getAssessmentRunAgentAMIAndAge(mockAPIs, "")
			assert.Equal(t, tc.expectedOutput, output)
			assert.Equal(t, tc.expectedError, err)
		})
	}

}

// TestDownloadFile needs internet access
func TestDownloadFile(t *testing.T) {
	url := "https://golangcode.com/images/avatar.jpg"
	path := "./avatar.jpg"

	err := downloadFile(path, url)
	if err != nil {
		t.Fatalf("Expected err to be nil but it was: %s", err)
	}

	err = deleteFile(path)
	if err != nil {
		t.Fatalf("Expected err to be nil but it was: %s", err)
	}
}

func TestGetReportFindings(t *testing.T) {
	logrus.SetOutput(ioutil.Discard)
	expectedFindings := []inspectorReportFinding{
		{
			RulePackageName: "CIS Operating System Security Configuration Benchmarks-1.0",
			High:            "2581",
			Medium:          "0",
			Low:             "0",
			Informational:   "232",
			Comments:        "**EXCEPTION:** Description here",
		},
		{
			RulePackageName: "Common Vulnerabilities and Exposures-1.1",
			High:            "29",
			Medium:          "46",
			Low:             "0",
			Informational:   "0",
			Comments:        "NEW_FINDING",
		},
		{
			RulePackageName: "Runtime Behavior Analysis-1.0",
			High:            "0",
			Medium:          "0",
			Low:             "23",
			Informational:   "44",
			Comments:        "NEW_FINDING",
		},
		{
			RulePackageName: "Security Best Practices-1.0",
			High:            "0",
			Medium:          "0",
			Low:             "0",
			Informational:   "0",
			Comments:        "",
		},
	}

	// Create copy of test inspector report for testing so original isn't deleted
	fileName := "test.html"
	err := copy("../../test/data/inspector_report_test.html", fileName)
	if err != nil {
		log.Fatalf("Error copying file: %s\n", err)
	}

	comments := parseCommentsFile("../../test/data/comments.yaml")
	report := inspectorReport{AccountID: "111111111111"}

	findings, err := getReportFindings(fileName, comments, report)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedFindings, findings) {
		t.Fatalf("Expected %s, got %s", expectedFindings, findings)
	}
}

func TestGetAgeInDays(t *testing.T) {
	expectedResult := 7
	// Get date that is 7 days ago from today
	today := time.Now()
	weekAgo := today.AddDate(0, 0, -7).Format(time.RFC3339)

	// Convert to string for function
	actualResult := getAgeInDays(weekAgo)

	if actualResult != expectedResult {
		t.Fatalf("Expected %d days, got %d days", expectedResult, actualResult)
	}
}

func TestDeleteFile(t *testing.T) {
	// Create file, delete it, then check if it was deleted / still exists
	filePath := "./dummy.txt"
	_, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("Expected err to be nil but it was: %s", err)
	}

	err = deleteFile(filePath)
	if err != nil {
		t.Fatalf("Expected err to be nil but it was: %s", err)
	}

	_, err = os.Stat(filePath)
	if !os.IsNotExist(err) {
		t.Fatalf("Expected err to be nil but it was: %s", err)
	}
}

func TestParseReportTable(t *testing.T) {
	expectedResult := [][]string{
		{"CIS Operating System Security Configuration Benchmarks-1.0", "2581", "0", "0", "232"},
		{"Common Vulnerabilities and Exposures-1.1", "29", "46", "0", "0"},
		{"Runtime Behavior Analysis-1.0", "0", "0", "23", "44"},
		{"Security Best Practices-1.0", "0", "0", "0", "0"},
	}

	result, err := parseReportTable("../../test/data/inspector_report_test.html")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedResult, result) {
		t.Fatalf("Expected %s, got %s", expectedResult, result)
	}
}

func TestGetAmiAgeMap(t *testing.T) {
	// Pass portion of describe images API response for test
	instancesList := &ec2.DescribeImagesOutput{
		Images: []*ec2.Image{
			{
				CreationDate:  aws.String("2019-07-07T05:58:28.000Z"),
				Description:   aws.String("AMI with metrics provider, ssm, ossec, awslogs, code deploy & inspector"),
				ImageId:       aws.String("ami-01afe9fb62487c917"),
				ImageLocation: aws.String("111111111111/encrypted-amzn2-ami-k8s-2.0-ssm-ossec-awslogs-inspector-2019-07-07"),
				ImageType:     aws.String("machine"),
				Name:          aws.String("encrypted-amzn2-ami-k8s-2.0-ssm-ossec-awslogs-inspector-2019-07-07"),
			},
			{
				CreationDate:  aws.String("2019-07-07T05:38:28.000Z"),
				Description:   aws.String("AMI for egress proxy with squid proxy, metrics provider, ssm, ossec, awslogs, code deploy & inspector"),
				Hypervisor:    aws.String("xen"),
				ImageId:       aws.String("ami-0d69650d24f16e93a"),
				ImageLocation: aws.String("111111111111/encrypted-amzn2-ami-hvm-2.0-squid-ssm-ossec-awslogs-inspector-2019-07-07"),
				ImageType:     aws.String("machine"),
				Name:          aws.String("encrypted-amzn2-ami-hvm-2.0-squid-ssm-ossec-awslogs-inspector-2019-07-07"),
			},
		},
	}

	expectedResult := map[string]int{
		"encrypted-amzn2-ami-k8s-2.0-ssm-ossec-awslogs-inspector-2019-07-07":       getAgeInDays("2019-07-07T05:58:28.000Z"),
		"encrypted-amzn2-ami-hvm-2.0-squid-ssm-ossec-awslogs-inspector-2019-07-07": getAgeInDays("2019-07-07T05:38:28.000Z"),
	}

	result := getAmiAgeMap(instancesList)

	if !reflect.DeepEqual(result, expectedResult) {
		t.Fatalf("Expected %v, got %v", expectedResult, result)
	}

}

func TestGetAmiList(t *testing.T) {
	// Pass portion of list instances API response for test
	instancesList := &ec2.DescribeInstancesOutput{
		Reservations: []*ec2.Reservation{
			{
				Instances: []*ec2.Instance{
					{
						ImageId: aws.String("ami-1234"),
					},
				},
				OwnerId:       aws.String("111111111111"),
				RequesterId:   aws.String("940372691376"),
				ReservationId: aws.String("r-05c3b42e310f42c23"),
			},
			{
				Instances: []*ec2.Instance{
					{
						ImageId: aws.String("ami-4444"),
					},
					{
						ImageId: aws.String("ami-555"),
					},
				},
				OwnerId:       aws.String("111111111111"),
				RequesterId:   aws.String("940372691376"),
				ReservationId: aws.String("r-0d2fb4dab0c28956a"),
			},
		},
	}

	expectedResult := []string{"ami-1234", "ami-4444", "ami-555"}
	result := getAmiList(instancesList)

	if !reflect.DeepEqual(result, expectedResult) {
		t.Fatalf("Expected %s, got %s", expectedResult, result)
	}

}

func TestUnique(t *testing.T) {
	testList := []string{"a", "a", "b", "c", "c"}
	expectedResult := []string{"a", "b", "c"}

	result := unique(testList)

	if !reflect.DeepEqual(result, expectedResult) {
		t.Fatalf("Expected %s, got %s", expectedResult, result)
	}
}

func copy(src, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dst, data, 0644)
	if err != nil {
		return err
	}
	return nil
}
