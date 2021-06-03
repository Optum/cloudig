package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"github.com/aws/aws-sdk-go/service/health"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/inspector"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/support"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/health/healthiface"
	"github.com/aws/aws-sdk-go/service/inspector/inspectoriface"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/aws/aws-sdk-go/service/support/supportiface"
)

// APIs represent the different API calls available to the AWS client
type APIs interface {
	EC2SVC
	TrustedAdvisorSVC
	ConfigServiceSVC
	InspectorSVC
	STSSVC
	IAMSVC
	HealthSVC
	ECRSVC
	CloudTrailSVC
	AthenaSVC
}

// Client is the client for AWS API operations
type Client struct {
	EC2            ec2iface.EC2API
	TrustedAdvisor supportiface.SupportAPI
	AWSConfig      configserviceiface.ConfigServiceAPI
	Inspector      inspectoriface.InspectorAPI
	STS            stsiface.STSAPI
	IAM            iamiface.IAMAPI
	Health         healthiface.HealthAPI
	ECR            ecriface.ECRAPI
	CloudTrail     cloudtrailiface.CloudTrailAPI
	Athena         athenaiface.AthenaAPI
}

// NewClient creates a Client object that implement all the methods in the APIs interface
func NewClient(sess *session.Session) APIs {
	config := constructAWSConfig()
	return &Client{
		EC2:            ec2.New(sess, config),
		TrustedAdvisor: support.New(sess, config),
		AWSConfig:      configservice.New(sess, config),
		Inspector:      inspector.New(sess, config),
		STS:            sts.New(sess, config),
		IAM:            iam.New(sess, config),
		Health:         health.New(sess, config),
		ECR:            ecr.New(sess, config),
		CloudTrail:     cloudtrail.New(sess, config),
		Athena:         athena.New(sess, config),
	}
}

// NewClientAsAssumeRole creates a Client object that assumes a role
func NewClientAsAssumeRole(sess *session.Session, roleARN string) APIs {
	creds := getRoleCredentials(sess, roleARN)
	config := constructAWSConfig().WithCredentials(creds)
	return &Client{
		EC2:            ec2.New(sess, config),
		TrustedAdvisor: support.New(sess, config),
		AWSConfig:      configservice.New(sess, config),
		Inspector:      inspector.New(sess, config),
		STS:            sts.New(sess, config),
		IAM:            iam.New(sess, config),
		Health:         health.New(sess, config),
		ECR:            ecr.New(sess, config),
		CloudTrail:     cloudtrail.New(sess, config),
		Athena:         athena.New(sess, config),
	}
}

// NewAuthenticatedSession creates an AWS Session using the credentials from the running environment
func NewAuthenticatedSession(region string) (*session.Session, error) {
	sess, err := session.NewSession(aws.NewConfig().WithRegion(region))
	if err != nil {
		return nil, err
	}
	return sess, err
}

// Function that gets credentials for non-parent accounts
func getRoleCredentials(sess *session.Session, roleARN string) (creds *credentials.Credentials) {
	return stscreds.NewCredentials(sess, roleARN)
}

// constructAWSConfig is helper function to create and return pointer to aws config
func constructAWSConfig() *aws.Config {
	config := aws.NewConfig()
	if logrus.GetLevel() >= 5 {
		config.WithCredentialsChainVerboseErrors(true).
			WithLogLevel(aws.LogDebugWithHTTPBody).
			WithLogger(aws.LoggerFunc(func(args ...interface{}) {
				logrus.Debugf(fmt.Sprintln(args...))
			}))
	}
	return config
}
