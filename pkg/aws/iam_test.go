package aws

import (
	"reflect"
	"testing"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestClient_GetRolesFromTags(t *testing.T) {
	// sess, _ := NewAuthenticatedSession("us-east-1")
	// roles, err := NewClient(sess).GetRolesFromTags(map[string]string{"terraform": "true"})
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Println(roles, len(roles))
	// t.Fail()
	type args struct {
		tags map[string]string
	}
	tests := []struct {
		name                    string
		args                    args
		apiListRolesResponse    *iam.ListRolesOutput
		apiListRoleTagsResponse *iam.ListRoleTagsOutput
		want                    []string
		wantErr                 bool
	}{
		{
			name: "noTags#1",
			args: args{tags: map[string]string{}},
			apiListRolesResponse: &iam.ListRolesOutput{
				Roles: []*iam.Role{
					{Arn: aws.String("arn:aws:iam::111111111111:role/SecurityAutomationLambda-stage"), RoleName: aws.String("SecurityAutomationLambda-stage")},
					{Arn: aws.String("arn:aws:iam::111111111111:role/SESLogstream-okra"), RoleName: aws.String("SESLogstream-okra")},
					{Arn: aws.String("arn:aws:iam::111111111111:role/eks-managed-dig-green-okra"), RoleName: aws.String("eks-managed-dig-green-okra")},
				},
				IsTruncated: aws.Bool(false),
			},
			apiListRoleTagsResponse: &iam.ListRoleTagsOutput{Tags: []*iam.Tag{
				{Key: aws.String("terraform"), Value: aws.String("true")},
				{Key: aws.String("version"), Value: aws.String("1.1")},
			}},
			want:    []string{"arn:aws:iam::111111111111:role/SecurityAutomationLambda-stage", "arn:aws:iam::111111111111:role/SESLogstream-okra", "arn:aws:iam::111111111111:role/eks-managed-dig-green-okra"},
			wantErr: false,
		},
		{
			name: "singleTag#2",
			args: args{tags: map[string]string{"terraform": "true"}},
			apiListRolesResponse: &iam.ListRolesOutput{
				Roles: []*iam.Role{
					{Arn: aws.String("arn:aws:iam::111111111111:role/SecurityAutomationLambda-stage"), RoleName: aws.String("SecurityAutomationLambda-stage")},
					{Arn: aws.String("arn:aws:iam::111111111111:role/SESLogstream-okra"), RoleName: aws.String("SESLogstream-okra")},
					{Arn: aws.String("arn:aws:iam::111111111111:role/eks-managed-dig-green-okra"), RoleName: aws.String("eks-managed-dig-green-okra")},
				},
				IsTruncated: aws.Bool(false),
			},
			apiListRoleTagsResponse: &iam.ListRoleTagsOutput{Tags: []*iam.Tag{
				{Key: aws.String("terraform"), Value: aws.String("true")},
				{Key: aws.String("version"), Value: aws.String("1.1")},
			}},
			want:    []string{"arn:aws:iam::111111111111:role/SecurityAutomationLambda-stage", "arn:aws:iam::111111111111:role/SESLogstream-okra", "arn:aws:iam::111111111111:role/eks-managed-dig-green-okra"},
			wantErr: false,
		},
		{
			name: "multiTag#3",
			args: args{tags: map[string]string{"terraform": "true", "version": "1.1"}},
			apiListRolesResponse: &iam.ListRolesOutput{
				Roles: []*iam.Role{
					{Arn: aws.String("arn:aws:iam::111111111111:role/SecurityAutomationLambda-stage"), RoleName: aws.String("SecurityAutomationLambda-stage")},
					{Arn: aws.String("arn:aws:iam::111111111111:role/SESLogstream-okra"), RoleName: aws.String("SESLogstream-okra")},
					{Arn: aws.String("arn:aws:iam::111111111111:role/eks-managed-dig-green-okra"), RoleName: aws.String("eks-managed-dig-green-okra")},
				},
				IsTruncated: aws.Bool(false),
			},
			apiListRoleTagsResponse: &iam.ListRoleTagsOutput{Tags: []*iam.Tag{
				{Key: aws.String("terraform"), Value: aws.String("true")},
				{Key: aws.String("version"), Value: aws.String("1.1")},
			}},
			want:    []string{"arn:aws:iam::111111111111:role/SecurityAutomationLambda-stage", "arn:aws:iam::111111111111:role/SESLogstream-okra", "arn:aws:iam::111111111111:role/eks-managed-dig-green-okra"},
			wantErr: false,
		},
		{
			name: "multiTag#4",
			args: args{tags: map[string]string{"terraform": "true", "version": "1.2"}},
			apiListRolesResponse: &iam.ListRolesOutput{
				Roles: []*iam.Role{
					{Arn: aws.String("arn:aws:iam::111111111111:role/SecurityAutomationLambda-stage"), RoleName: aws.String("SecurityAutomationLambda-stage")},
					{Arn: aws.String("arn:aws:iam::111111111111:role/SESLogstream-okra"), RoleName: aws.String("SESLogstream-okra")},
					{Arn: aws.String("arn:aws:iam::111111111111:role/eks-managed-dig-green-okra"), RoleName: aws.String("eks-managed-dig-green-okra")},
				},
				IsTruncated: aws.Bool(false),
			},
			apiListRoleTagsResponse: &iam.ListRoleTagsOutput{Tags: []*iam.Tag{
				{Key: aws.String("terraform"), Value: aws.String("true")},
				{Key: aws.String("version"), Value: aws.String("1.1")},
			}},
			want:    []string{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockIAMAPI := mocks.NewMockIAMAPI(mockCtrl)
			mockIAMAPI.EXPECT().ListRoles(&iam.ListRolesInput{}).Return(tt.apiListRolesResponse, nil)
			for _, v := range tt.apiListRolesResponse.Roles {
				mockIAMAPI.EXPECT().ListRoleTags(&iam.ListRoleTagsInput{RoleName: v.RoleName}).Return(tt.apiListRoleTagsResponse, nil).AnyTimes()
			}
			client := &Client{
				IAM: mockIAMAPI,
			}
			got, err := client.GetRolesFromTags(tt.args.tags)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetRolesFromTags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !assert.ElementsMatch(t, got, tt.want) {
				t.Errorf("Client.GetRolesFromTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_containsAllTags(t *testing.T) {
	type args struct {
		checkTags map[string]string
		roleTags  []*iam.Tag
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "present#1",
			args: args{
				checkTags: map[string]string{"terraform": "true", "accountType": "prod"},
				roleTags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
			},
			want: true,
		},
		{
			name: "present#2",
			args: args{
				checkTags: map[string]string{"launchPad": "true", "version": "1.2"},
				roleTags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
			},
			want: true,
		},
		{
			name: "missingTag#3",
			args: args{
				checkTags: map[string]string{"launchPad": "true", "version": "1.3", "sts": "true"},
				roleTags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
			},
			want: false,
		},
		{
			name: "wrongValue#4",
			args: args{
				checkTags: map[string]string{"launchPad": "true", "version": "1.3"},
				roleTags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
			},
			want: false,
		},
		{
			name: "wrongkey#5",
			args: args{
				checkTags: map[string]string{"launchPad": "true", "versions": "1.2"},
				roleTags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
			},
			want: false,
		},
		{
			name: "lowecase#6",
			args: args{
				checkTags: map[string]string{"launchpad": "true", "versions": "1.2"},
				roleTags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
			},
			want: false,
		},
		{
			name: "noRoleTags#7",
			args: args{
				checkTags: map[string]string{"launchPad": "true", "versions": "1.2"},
				roleTags:  []*iam.Tag{},
			},
			want: false,
		},
		{
			name: "noCheckTags#8",
			args: args{
				checkTags: map[string]string{},
				roleTags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAllTags(tt.args.checkTags, tt.args.roleTags); got != tt.want {
				t.Errorf("containsAllTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_containsTag(t *testing.T) {
	type args struct {
		tags []*iam.Tag
		k    string
		v    string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "present#1",
			args: args{
				tags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
				k: "terraform",
				v: "true",
			},
			want: true,
		},
		{
			name: "present#2",
			args: args{
				tags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
				k: "accountType",
				v: "prod",
			},
			want: true,
		},
		{
			name: "wrongValue#3",
			args: args{
				tags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
				k: "terraform",
				v: "false",
			},
			want: false,
		},
		{
			name: "wrongkey#4",
			args: args{
				tags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
				k: "versions",
				v: "1.2",
			},
			want: false,
		},
		{
			name: "lowecase#5",
			args: args{
				tags: []*iam.Tag{
					{Key: aws.String("launchPad"), Value: aws.String("true")},
					{Key: aws.String("terraform"), Value: aws.String("true")},
					{Key: aws.String("accountType"), Value: aws.String("prod")},
					{Key: aws.String("version"), Value: aws.String("1.2")},
				},
				k: "accountType",
				v: "Prod",
			},
			want: false,
		},
		{
			name: "noRoleTags#6",
			args: args{
				tags: []*iam.Tag{},
				k:    "accountType",
				v:    "Prod",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsTag(tt.args.tags, tt.args.k, tt.args.v); got != tt.want {
				t.Errorf("containsTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mergePolicyActions(t *testing.T) {
	type args struct {
		policyDocs []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "simplePolicy#1",
			args: args{[]string{
				`{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Action": "*",
							"Resource": "*"
						}
					]
				}`,
			}},
			want:    []string{"*"},
			wantErr: false,
		},
		{
			name: "complexPolicy#2",
			args: args{[]string{
				`{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Action": "*",
							"Resource": "*"
						}
					]
				}`,
				`{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Sid": "",
							"Effect": "Allow",
							"Action": [
								"s3:PutObject",
								"s3:ListBucket",
								"s3:GetObject",
								"s3:GetBucketAcl",
								"s3:DeleteObject"
							],
							"Resource": [
								"arn:aws:s3:::dig-stage-dsfds/*",
								"arn:aws:s3:::dig-stage-sdfdsf"
							]
						},
						{
							"Sid": "",
							"Effect": "Allow",
							"Action": "events:PutEvents",
							"Resource": "*"
						}
					]
				}
				`,
			}},
			want:    []string{"*", "s3:PutObject", "s3:ListBucket", "s3:GetObject", "s3:GetBucketAcl", "s3:DeleteObject", "events:PutEvents"},
			wantErr: false,
		},
		{
			name: "errorPolicy#3",
			args: args{[]string{
				`{
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Action": "*,
							"Resource": "*",
						}
					]
				}`,
			}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "NoPolicy#4",
			args:    args{[]string{}},
			want:    []string{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mergePolicyActions(tt.args.policyDocs)
			if (err != nil) != tt.wantErr {
				t.Errorf("mashPolices() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mashPolices() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getNetIAMRolePermissions(t *testing.T) {
	// 	sess, _ := NewAuthenticatedSession("us-east-1")
	//  client := NewClient(sess)
	// 	result, err := client.getNetIAMRolePermissions("111111111111_SplunkRole")
	// 	if err != nil {
	// 		log.Println(err)
	// 	}
	// 	log.Println(result, len(result))
	// 	t.Fail()
	type args struct {
		roleName string
	}
	tests := []struct {
		name                                   string
		args                                   args
		mockedListRolePoliciesResponse         *iam.ListRolePoliciesOutput
		mockedGetRolePolicyResponse            *iam.GetRolePolicyOutput
		mockedListAttachedRolePoliciesResponse *iam.ListAttachedRolePoliciesOutput
		mockedGetPolicyResponse                *iam.GetPolicyOutput
		mockedGetPolicyVersionResponse         *iam.GetPolicyVersionOutput
		want                                   []string
		wantErr                                bool
	}{
		{
			name:                           "simpleRolewithAttachedPolicy#1",
			args:                           args{roleName: "simpleRolewithAttachedPolicy"},
			mockedListRolePoliciesResponse: &iam.ListRolePoliciesOutput{},
			mockedGetRolePolicyResponse:    &iam.GetRolePolicyOutput{},
			mockedListAttachedRolePoliciesResponse: &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []*iam.AttachedPolicy{
					{PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"), PolicyName: aws.String("AmazonECSTaskExecutionRolePolicy")},
				},
			},
			mockedGetPolicyResponse: &iam.GetPolicyOutput{
				Policy: &iam.Policy{
					Arn:              aws.String("arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"),
					PolicyName:       aws.String("AmazonECSTaskExecutionRolePolicy"),
					DefaultVersionId: aws.String("v1"),
				},
			},
			mockedGetPolicyVersionResponse: &iam.GetPolicyVersionOutput{PolicyVersion: &iam.PolicyVersion{
				Document:  aws.String("%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22ecr%3AGetAuthorizationToken%22%2C%0A%20%20%20%20%20%20%20%20%22ecr%3ABatchCheckLayerAvailability%22%2C%0A%20%20%20%20%20%20%20%20%22ecr%3AGetDownloadUrlForLayer%22%2C%0A%20%20%20%20%20%20%20%20%22ecr%3ABatchGetImage%22%2C%0A%20%20%20%20%20%20%20%20%22logs%3ACreateLogStream%22%2C%0A%20%20%20%20%20%20%20%20%22logs%3APutLogEvents%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D"),
				VersionId: aws.String("v1"),
			}},
			want: []string{
				"ecr:GetAuthorizationToken",
				"ecr:BatchCheckLayerAvailability",
				"ecr:GetDownloadUrlForLayer",
				"ecr:BatchGetImage",
				"logs:CreateLogStream",
				"logs:PutLogEvents",
			},
			wantErr: false,
		},
		{
			name:                           "simpleRolewithInlinePolicy#2",
			args:                           args{roleName: "simpleRolewithInlinePolicy"},
			mockedListRolePoliciesResponse: &iam.ListRolePoliciesOutput{PolicyNames: []*string{aws.String("S3Policy")}},
			mockedGetRolePolicyResponse: &iam.GetRolePolicyOutput{
				PolicyDocument: aws.String("%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3APutObject%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AListBucket%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AGetObject%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AGetBucketAcl%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3ADeleteObject%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3As3%3A%3A%3Aoid-stage-dsfds%2F%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3As3%3A%3A%3Aoid-stage-sdfdsf%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22events%3APutEvents%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D"),
				PolicyName:     aws.String("S3Policy"),
				RoleName:       aws.String("simpleRolewithInlinePolicy"),
			},
			mockedListAttachedRolePoliciesResponse: &iam.ListAttachedRolePoliciesOutput{},
			mockedGetPolicyResponse:                &iam.GetPolicyOutput{},
			mockedGetPolicyVersionResponse:         &iam.GetPolicyVersionOutput{},
			want: []string{
				"s3:PutObject",
				"s3:ListBucket",
				"s3:GetObject",
				"s3:GetBucketAcl",
				"s3:DeleteObject",
				"events:PutEvents",
			},
			wantErr: false,
		},
		{
			name:                           "RolewithBothInlineAndAttachedPolicy#3",
			args:                           args{roleName: "simpleRolewithInlinePolicy"},
			mockedListRolePoliciesResponse: &iam.ListRolePoliciesOutput{PolicyNames: []*string{aws.String("S3Policy")}},
			mockedGetRolePolicyResponse: &iam.GetRolePolicyOutput{
				PolicyDocument: aws.String("%7B%0A%20%20%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3APutObject%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AListBucket%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AGetObject%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3AGetBucketAcl%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22s3%3ADeleteObject%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3As3%3A%3A%3Aoid-stage-dsfds%2F%2A%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%22arn%3Aaws%3As3%3A%3A%3Aoid-stage-sdfdsf%22%0A%20%20%20%20%20%20%20%20%20%20%20%20%5D%0A%20%20%20%20%20%20%20%20%7D%2C%0A%20%20%20%20%20%20%20%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Sid%22%3A%20%22%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Action%22%3A%20%22events%3APutEvents%22%2C%0A%20%20%20%20%20%20%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%5D%0A%7D"),
				PolicyName:     aws.String("S3Policy"),
				RoleName:       aws.String("simpleRolewithInlinePolicy"),
			},
			mockedListAttachedRolePoliciesResponse: &iam.ListAttachedRolePoliciesOutput{
				AttachedPolicies: []*iam.AttachedPolicy{
					{PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"), PolicyName: aws.String("AmazonECSTaskExecutionRolePolicy")},
				},
			},
			mockedGetPolicyResponse: &iam.GetPolicyOutput{
				Policy: &iam.Policy{
					Arn:              aws.String("arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"),
					PolicyName:       aws.String("AmazonECSTaskExecutionRolePolicy"),
					DefaultVersionId: aws.String("v1"),
				},
			},
			mockedGetPolicyVersionResponse: &iam.GetPolicyVersionOutput{PolicyVersion: &iam.PolicyVersion{
				Document:  aws.String("%7B%0A%20%20%22Version%22%3A%20%222012-10-17%22%2C%0A%20%20%22Statement%22%3A%20%5B%0A%20%20%20%20%7B%0A%20%20%20%20%20%20%22Effect%22%3A%20%22Allow%22%2C%0A%20%20%20%20%20%20%22Action%22%3A%20%5B%0A%20%20%20%20%20%20%20%20%22ecr%3AGetAuthorizationToken%22%2C%0A%20%20%20%20%20%20%20%20%22ecr%3ABatchCheckLayerAvailability%22%2C%0A%20%20%20%20%20%20%20%20%22ecr%3AGetDownloadUrlForLayer%22%2C%0A%20%20%20%20%20%20%20%20%22ecr%3ABatchGetImage%22%2C%0A%20%20%20%20%20%20%20%20%22logs%3ACreateLogStream%22%2C%0A%20%20%20%20%20%20%20%20%22logs%3APutLogEvents%22%0A%20%20%20%20%20%20%5D%2C%0A%20%20%20%20%20%20%22Resource%22%3A%20%22%2A%22%0A%20%20%20%20%7D%0A%20%20%5D%0A%7D"),
				VersionId: aws.String("v1"),
			}},
			want: []string{
				"s3:PutObject",
				"s3:ListBucket",
				"s3:GetObject",
				"s3:GetBucketAcl",
				"s3:DeleteObject",
				"events:PutEvents",
				"ecr:GetAuthorizationToken",
				"ecr:BatchCheckLayerAvailability",
				"ecr:GetDownloadUrlForLayer",
				"ecr:BatchGetImage",
				"logs:CreateLogStream",
				"logs:PutLogEvents",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockIAMAPI := mocks.NewMockIAMAPI(mockCtrl)
			mockIAMAPI.EXPECT().ListRolePolicies(&iam.ListRolePoliciesInput{RoleName: aws.String(tt.args.roleName)}).Return(tt.mockedListRolePoliciesResponse, nil)
			for _, v := range tt.mockedListRolePoliciesResponse.PolicyNames {
				mockIAMAPI.EXPECT().GetRolePolicy(&iam.GetRolePolicyInput{PolicyName: v, RoleName: aws.String(tt.args.roleName)}).Return(tt.mockedGetRolePolicyResponse, nil).AnyTimes()
			}
			mockIAMAPI.EXPECT().ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{RoleName: aws.String(tt.args.roleName)}).Return(tt.mockedListAttachedRolePoliciesResponse, nil)
			for _, v := range tt.mockedListAttachedRolePoliciesResponse.AttachedPolicies {
				mockIAMAPI.EXPECT().GetPolicy(&iam.GetPolicyInput{PolicyArn: v.PolicyArn}).Return(tt.mockedGetPolicyResponse, nil).AnyTimes()
				mockIAMAPI.EXPECT().GetPolicyVersion(&iam.GetPolicyVersionInput{PolicyArn: v.PolicyArn, VersionId: tt.mockedGetPolicyResponse.Policy.DefaultVersionId}).Return(tt.mockedGetPolicyVersionResponse, nil).AnyTimes()
			}
			client := &Client{
				IAM: mockIAMAPI,
			}
			got, err := client.getNetIAMRolePermissions(tt.args.roleName)
			if (err != nil) != tt.wantErr {
				t.Errorf("getNetIAMRolePermissions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getNetIAMRolePermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}

// func TestClient_GetNetIAMPermissionsForRoles(t *testing.T) {
// 	sess, _ := NewAuthenticatedSession("us-east-1")
// 	client := NewClient(sess)
// 	result, err := client.GetNetIAMPermissionsForRoles([]string{"arn:aws:iam::111111111111:role/cluster-autoscaler-greencherry-dev",
// 		"arn:aws:iam::111111111111:role/cluster-autoscaler-greencherry-okra",
// 		"arn:aws:iam::111111111111:role/cluster-autoscaler-greencherry-stage",
// 		"arn:aws:iam::111111111111:role/cognito-access-policy-dce",
// 		"arn:aws:iam::111111111111:role/config-server-greencherry-dev",
// 		"arn:aws:iam::111111111111:role/config-server-greencherry-okra",
// 		"arn:aws:iam::111111111111:role/config-server-greencherry-stage",
// 		"arn:aws:iam::111111111111:role/configuration-recorder-role",
// 		"arn:aws:iam::111111111111:role/db-utility-greencherry-dev",
// 		"arn:aws:iam::111111111111:role/db-utility-greencherry-okra",
// 		"arn:aws:iam::111111111111:role/db-utility-greencherry-stage",
// 		"arn:aws:iam::111111111111:role/dev-exodos-role",
// 		"arn:aws:iam::111111111111:role/dev-exodos-secret-updater-role",
// 		"arn:aws:iam::111111111111:role/ecs_task_execution_role_name_dev",
// 		"arn:aws:iam::111111111111:role/ecs_task_execution_role_name_stage",
// 	})
// 	if err != nil {
// 		log.Println(err)
// 	}
// 	log.Println(result, len(result))
// 	t.Fail()
// }

func Test_runInBatches(t *testing.T) {
	type args struct {
		//targetFunc  func(string)
		targetSlice []string
		limit       int
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "#1",
			args: args{
				targetSlice: []string{"a", "b", "c", "d"},
				limit:       10,
			},
			want: []string{"aa", "ba", "ca", "da"},
		},
		{
			name: "#2",
			args: args{
				targetSlice: []string{},
				limit:       10,
			},
			want: []string{},
		},
		{
			name: "#3",
			args: args{
				targetSlice: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23"},
				limit:       10,
			},
			want: []string{"13a", "14a", "15a", "16a", "17a", "18a", "19a", "20a", "21a", "22a", "23a", "1a", "2a", "3a", "4a", "5a", "6a", "7a", "8a", "9a", "10a", "11a", "12a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := make(chan string, len(tt.args.targetSlice))
			runInBatches(func(v string) {
				output <- v + "a"
			}, tt.args.targetSlice, tt.args.limit)
			results := make([]string, 0)
			// close chanel
			close(output)
			for v := range output {
				results = append(results, v)
			}
			if !assert.ElementsMatch(t, results, tt.want) {
				t.Errorf("runInBatches() = %v, want %v", results, tt.want)
			}
		})
	}

}
