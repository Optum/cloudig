package aws

import (
	"github.com/aws/aws-sdk-go/aws"
)

// Contains tells whether slice of strings 'ss' contains string 's'.
func Contains(ss []string, s string) bool {
	for _, n := range ss {
		if s == n {
			return true
		}
	}
	return false
}

// SdkStringContains tells whether slice of pointers of strings 'ss' contains pointer string 's'.
func SdkStringContains(ss []*string, s *string) bool {
	for _, n := range ss {
		if aws.StringValue(s) == aws.StringValue(n) {
			return true
		}
	}
	return false
}
