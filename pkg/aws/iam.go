package aws

import (
	"encoding/json"
	"math"
	"net/url"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
)

// IAMSVC is a wrapper for IAM API calls
type IAMSVC interface {
	GetRolesFromTags(tags map[string]string) ([]string, error)
	GetNetIAMPermissionsForRoles(roleARNs []string) map[string][]string
}

type roleTagResult struct {
	roleTags []*iam.Tag
	roleARN  string
	err      error
}

const (
	parallelListRoleTagsAPILimit    int = 15 // AWS ratelimit @ 100 call per sec
	parallelRolePermissionsAPILimit int = 10
)

// GetRolesFromTags returns a list of IAM Roles with tags provided
// Please note, ListRoles doesn't get the tags - https://github.com/aws/aws-sdk-go/issues/2442
// this would mean calling ListRoleTags API for each role to get the tags
// we call this API in parallel to speed up the overall execution
func (client *Client) GetRolesFromTags(tags map[string]string) ([]string, error) {
	result, err := client.IAM.ListRoles(&iam.ListRolesInput{})
	if err != nil {
		return nil, err
	}
	roleARNs := make([]string, 0)
	for _, v := range result.Roles {
		roleARNs = append(roleARNs, aws.StringValue(v.Arn))
	}

	resultsTruncated := *result.IsTruncated
	marker := result.Marker
	for resultsTruncated {
		result, err := client.IAM.ListRoles(&iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		for _, v := range result.Roles {
			roleARNs = append(roleARNs, aws.StringValue(v.Arn))
		}
		resultsTruncated = *result.IsTruncated
		marker = result.Marker
	}
	// if there are no tags to validate, entire role slice is returned
	if len(tags) == 0 {
		return roleARNs, nil
	}

	output := make(chan roleTagResult, len(roleARNs))
	runInBatches(func(roleARN string) {
		ss := strings.Split(roleARN, "/")
		result, err := client.IAM.ListRoleTags(&iam.ListRoleTagsInput{RoleName: aws.String(ss[len(ss)-1])})
		output <- roleTagResult{result.Tags, roleARN, err}
	}, roleARNs, parallelListRoleTagsAPILimit)

	// close chanel
	close(output)

	roleARNsWithTags := make([]string, 0)
	// read from the chanel
	for v := range output {
		if v.err != nil {
			return nil, v.err
		}
		if containsAllTags(tags, v.roleTags) {
			roleARNsWithTags = append(roleARNsWithTags, v.roleARN)
		}
	}
	return roleARNsWithTags, nil
}

// containsAllTags find if given map of tags are present in slice of IAM tag
func containsAllTags(checkTags map[string]string, roleTags []*iam.Tag) bool {
	if len(checkTags) == 0 {
		return true
	}
	for k, v := range checkTags {
		if !containsTag(roleTags, k, v) {
			return false
		}
	}
	return true
}

// containsTag find if given key and value present in slice of IAM tag
func containsTag(tags []*iam.Tag, k, v string) bool {
	for _, tag := range tags {
		if k == *tag.Key && v == *tag.Value {
			return true
		}
	}
	return false
}

type rolePermissionResult struct {
	roleARN     string
	permissions []string
	err         error
}

// GetNetIAMPermissionsForRoles returns the IAM permissions for each role attached via different polices
func (client *Client) GetNetIAMPermissionsForRoles(roleARNs []string) map[string][]string {
	//  loop over each role and get all polices for a role
	//  call getNetIAMRolePermissions(client *Client,roleARN string) ([]string,error)

	output := make(chan rolePermissionResult, len(roleARNs))
	runInBatches(func(roleARN string) {
		ss := strings.Split(roleARN, "/")
		result, err := client.getNetIAMRolePermissions(ss[len(ss)-1])
		output <- rolePermissionResult{roleARN, result, err}
	}, roleARNs, parallelRolePermissionsAPILimit)

	// close chanel
	close(output)

	permissions := make(map[string][]string, 0)
	// read from the channel
	for v := range output {
		if v.err != nil {
			var errString string
			if awsErr, ok := v.err.(awserr.Error); ok {
				errString = awsErr.Message()
			} else {
				errString = v.err.Error()
			}
			permissions[v.roleARN] = []string{errString}
		} else {
			permissions[v.roleARN] = v.permissions
		}
	}

	return permissions
}

// getNetIAMRolePermissions returns the IAM permissions for the role attached via different polices
func (client *Client) getNetIAMRolePermissions(roleName string) ([]string, error) {
	policyDocuments := make([]string, 0)

	// check for inline polices
	resultRoleInlinePolices, err := client.IAM.ListRolePolicies(&iam.ListRolePoliciesInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, err
	}
	for _, policyName := range resultRoleInlinePolices.PolicyNames {
		resultRolePolicy, err := client.IAM.GetRolePolicy(&iam.GetRolePolicyInput{PolicyName: policyName, RoleName: aws.String(roleName)})
		if err != nil {
			return nil, err
		}
		decodedPolicyDoc, err := url.QueryUnescape(aws.StringValue(resultRolePolicy.PolicyDocument))
		if err != nil {
			return nil, err
		}
		policyDocuments = append(policyDocuments, decodedPolicyDoc)
	}

	// check for attached policies
	resultRoleAttachedPolices, err := client.IAM.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, err
	}

	// loop through each polices to get the policy document
	for _, policy := range resultRoleAttachedPolices.AttachedPolicies {
		resultPolicyOutput, err := client.IAM.GetPolicy(&iam.GetPolicyInput{PolicyArn: policy.PolicyArn})
		if err != nil {
			return nil, err
		}
		resultPolicyVersion, err := client.IAM.GetPolicyVersion(&iam.GetPolicyVersionInput{PolicyArn: policy.PolicyArn, VersionId: resultPolicyOutput.Policy.DefaultVersionId})
		if err != nil {
			return nil, err
		}
		decodedPolicyDoc, err := url.QueryUnescape(aws.StringValue(resultPolicyVersion.PolicyVersion.Document))
		if err != nil {
			return nil, err
		}
		policyDocuments = append(policyDocuments, decodedPolicyDoc)
	}

	// combine all policy document to get the net permissions
	return mergePolicyActions(policyDocuments)
}

// policyDocument defins the structure for a policy
type policyDocument struct {
	Version   string
	Statement []statementEntry
}

// statementEntry defins the structure for policy statement
type statementEntry struct {
	Effect   string
	Action   interface{} // support both string & []string
	Resource interface{} // support both string & []string
}

// mergePolicyActions combines policy actions from multiple statements and policy document
func mergePolicyActions(policyDocs []string) ([]string, error) {
	policyPermission := make([]string, 0)
	// loop over policyDocs
	for _, policyDoc := range policyDocs {
		doc := policyDocument{}
		// URL decode each policy doc

		err := json.Unmarshal([]byte(policyDoc), &doc)
		if err != nil {
			return nil, err
		}

		// TODO : handle deny polices
		// TODO : include resources
		for _, stmt := range doc.Statement {
			if stmt.Effect == "Allow" {
				switch stmt.Action.(type) {
				case []interface{}:
					for _, v := range stmt.Action.([]interface{}) {
						policyPermission = append(policyPermission, v.(string)) // we can bet on value to be string here
					}
				case interface{}:
					policyPermission = append(policyPermission, stmt.Action.(string))
				default: // possibly nil
					//policyPermission = append(policyPermission, stmt.Action.(string))
				}
			}
		}
	}

	return policyPermission, nil
}

// runInBatches takes a target function and run concurrently with maximum of 'limit' times
// to process the elements from targetSlice
func runInBatches(targetFunc func(string), targetSlice []string, limit int) {
	var wg sync.WaitGroup
	// determine the number of batches to get the results for all elements
	// each batch runs the targetfunction maximum of 'limit' times to get the results
	batchSize := int(math.Ceil(float64(len(targetSlice) / limit)))
	// total elements left to process
	elementsLeft := len(targetSlice)
	elementsIndex := 0
	for batchSize != -1 {
		// loopsize is going to be same as limit except for the last loop to capture the reminder
		loopSize := limit
		if elementsLeft < limit {
			loopSize = elementsLeft
		}
		wg.Add(loopSize)
		for i := 0; i < loopSize; i++ {
			go func(e string) {
				defer wg.Done()
				targetFunc(e)

			}(targetSlice[elementsIndex])
			elementsIndex++
		}
		wg.Wait()
		batchSize--
		elementsLeft = elementsLeft - limit
	}
}
