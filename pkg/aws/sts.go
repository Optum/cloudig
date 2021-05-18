package aws

import (
	"github.com/aws/aws-sdk-go/service/sts"
)

// STSSVC is a wrapper for STS API calls
type STSSVC interface {
	GetAccountID() (string, error)
}

// GetAccountID returns the AccountID associated with the current session
func (client *Client) GetAccountID() (string, error) {
	result, err := client.STS.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return *result.Account, nil
}
