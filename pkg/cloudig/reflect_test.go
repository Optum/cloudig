package cloudig

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/golang/mock/gomock"
	"github.com/kris-nova/logger"
)

func TestReflectReport_GetReport(t *testing.T) {
	// 	report := ReflectReport{}
	// 	sess, _ := awslocal.NewAuthenticatedSession("us-east-1")
	// 	client := awslocal.NewClient(sess)
	// 	comments := make([]Comments, 0)
	// 	err := report.GetReport(client, &comments)
	// 	if err != nil {
	// 		log.Println(err)
	// 	}
	// 	t.Fail()
	athenaResultSetUsage := &athena.ResultSet{
		ResultSetMetadata: &athena.ResultSetMetadata{ColumnInfo: []*athena.ColumnInfo{
			{
				Name: aws.String("arn"),
				Type: aws.String("varchar"),
			},
			{
				Name: aws.String("eventsource"),
				Type: aws.String("varchar"),
			},
			{
				Name: aws.String("eventname"),
				Type: aws.String("varchar"),
			},
			{
				Name: aws.String("count"),
				Type: aws.String("varchar"),
			},
		}},
		Rows: []*athena.Row{
			{
				Data: []*athena.Datum{
					{VarCharValue: aws.String("arn")},
					{VarCharValue: aws.String("eventsource")},
					{VarCharValue: aws.String("eventname")},
					{VarCharValue: aws.String("count")},
				},
			},
			{
				Data: []*athena.Datum{
					{VarCharValue: aws.String("arn:aws:iam::111111111111:role/AWS_111111111111_Read")},
					{VarCharValue: aws.String("iam.amazonaws.com")},
					{VarCharValue: aws.String("UpdateAssumeRolePolicy")},
					{VarCharValue: aws.String("1")},
				},
			},
		},
	}

	athenaResultSetError := &athena.ResultSet{
		ResultSetMetadata: &athena.ResultSetMetadata{ColumnInfo: []*athena.ColumnInfo{
			{
				Name: aws.String("arn"),
				Type: aws.String("varchar"),
			},
			{
				Name: aws.String("eventsource"),
				Type: aws.String("varchar"),
			},
			{
				Name: aws.String("eventname"),
				Type: aws.String("varchar"),
			},
			{
				Name: aws.String("errorcode"),
				Type: aws.String("varchar"),
			},
			{
				Name: aws.String("count"),
				Type: aws.String("varchar"),
			},
		}},
		Rows: []*athena.Row{
			{
				Data: []*athena.Datum{
					{VarCharValue: aws.String("arn")},
					{VarCharValue: aws.String("eventsource")},
					{VarCharValue: aws.String("eventname")},
					{VarCharValue: aws.String("errorcode")},
					{VarCharValue: aws.String("count")},
				},
			},
			{
				Data: []*athena.Datum{
					{VarCharValue: aws.String("arn:aws:iam::111111111111:role/AWS_111111111111_Read")},
					{VarCharValue: aws.String("iam.amazonaws.com")},
					{VarCharValue: aws.String("UpdateAssumeRolePolicy")},
					{VarCharValue: aws.String("AccessDenied")},
					{VarCharValue: aws.String("1")},
				},
			},
		},
	}

	type args struct {
		comments []Comments
	}
	tests := []struct {
		name                                      string
		args                                      args
		initFindings                              []reflectFinding
		flags                                     ReflectFlags
		mockedGetS3LogPrefixForCloudTrailResponse *string
		mockedGetS3LogPrefixForCloudTrailError    error
		mockedGetTableforMetadataResponse         *string
		mockedGetTableforMetadataError            error
		mockedCreateTableFromMetadataResponse     *string
		mockedCreateTableFromMetadataError        error
		GetRolesFromTagsResponse                  []string
		GetRolesFromTagsError                     error
		mockedUsageReportRunQueryResponse         *athena.ResultSet
		mockedErrorReportRunQueryResponse         *athena.ResultSet
		mockedUsageReportRunQueryError            error
		mockedErrorReportRunQueryError            error
		GetNetIAMPermissionsForRolesResponse      map[string][]string
		updatedFindings                           []reflectFinding
		wantErr                                   bool
	}{
		{
			name: "s3LogPrefixFailure#1",
			args: args{
				[]Comments{},
			},
			initFindings: []reflectFinding{},
			flags:        NewReflectFlags("us-east-1", []string{"arn:aws:iam::111111111111:role/AWS_111111111111_Read"}, map[string]string{}, true, true, false, "", 1),
			mockedGetS3LogPrefixForCloudTrailResponse: nil,
			mockedGetS3LogPrefixForCloudTrailError:    errors.New("some error"),
			mockedGetTableforMetadataResponse:         nil,
			mockedGetTableforMetadataError:            nil,
			mockedCreateTableFromMetadataResponse:     nil,
			mockedCreateTableFromMetadataError:        nil,
			GetRolesFromTagsResponse:                  nil,
			GetRolesFromTagsError:                     nil,
			mockedUsageReportRunQueryResponse:         &athena.ResultSet{},
			mockedErrorReportRunQueryResponse:         &athena.ResultSet{},
			mockedUsageReportRunQueryError:            nil,
			mockedErrorReportRunQueryError:            nil,
			GetNetIAMPermissionsForRolesResponse:      map[string][]string{},
			updatedFindings:                           []reflectFinding{},
			wantErr:                                   true,
		},
		{
			name: "s3LogPrefixEmpty#2",
			args: args{
				[]Comments{},
			},
			initFindings: []reflectFinding{},
			flags:        NewReflectFlags("us-east-1", []string{"arn:aws:iam::111111111111:role/AWS_111111111111_Read"}, map[string]string{}, true, true, false, "", 1),
			mockedGetS3LogPrefixForCloudTrailResponse: nil,
			mockedGetS3LogPrefixForCloudTrailError:    nil,
			mockedGetTableforMetadataResponse:         nil,
			mockedGetTableforMetadataError:            nil,
			mockedCreateTableFromMetadataResponse:     nil,
			mockedCreateTableFromMetadataError:        nil,
			GetRolesFromTagsResponse:                  nil,
			GetRolesFromTagsError:                     nil,
			mockedUsageReportRunQueryResponse:         &athena.ResultSet{},
			mockedErrorReportRunQueryResponse:         &athena.ResultSet{},
			mockedUsageReportRunQueryError:            nil,
			mockedErrorReportRunQueryError:            nil,
			GetNetIAMPermissionsForRolesResponse:      map[string][]string{},
			updatedFindings:                           []reflectFinding{},
			wantErr:                                   true,
		},
		{
			name: "getExistingTableError#3",
			args: args{
				[]Comments{},
			},
			initFindings: []reflectFinding{},
			flags:        NewReflectFlags("us-east-1", []string{"arn:aws:iam::111111111111:role/AWS_111111111111_Read"}, map[string]string{}, true, true, false, "", 1),
			mockedGetS3LogPrefixForCloudTrailResponse: aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
			mockedGetS3LogPrefixForCloudTrailError:    nil,
			mockedGetTableforMetadataResponse:         nil,
			mockedGetTableforMetadataError:            errors.New("some error"),
			mockedCreateTableFromMetadataResponse:     nil,
			mockedCreateTableFromMetadataError:        errors.New("some error"),
			GetRolesFromTagsResponse:                  nil,
			GetRolesFromTagsError:                     nil,
			mockedUsageReportRunQueryResponse:         &athena.ResultSet{},
			mockedErrorReportRunQueryResponse:         &athena.ResultSet{},
			mockedUsageReportRunQueryError:            nil,
			mockedErrorReportRunQueryError:            nil,
			GetNetIAMPermissionsForRolesResponse:      map[string][]string{},
			updatedFindings:                           []reflectFinding{},
			wantErr:                                   true,
		},
		{
			name: "emptyGetExistingTable#4",
			args: args{
				[]Comments{},
			},
			initFindings: []reflectFinding{},
			flags:        NewReflectFlags("us-east-1", []string{"arn:aws:iam::111111111111:role/AWS_111111111111_Read"}, map[string]string{}, true, true, false, "", 1),
			mockedGetS3LogPrefixForCloudTrailResponse: aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
			mockedGetS3LogPrefixForCloudTrailError:    nil,
			mockedGetTableforMetadataResponse:         nil,
			mockedGetTableforMetadataError:            nil,
			mockedCreateTableFromMetadataResponse:     nil,
			mockedCreateTableFromMetadataError:        errors.New("some error"),
			GetRolesFromTagsResponse:                  nil,
			GetRolesFromTagsError:                     nil,
			mockedUsageReportRunQueryResponse:         &athena.ResultSet{},
			mockedErrorReportRunQueryResponse:         &athena.ResultSet{},
			mockedUsageReportRunQueryError:            nil,
			mockedErrorReportRunQueryError:            nil,
			GetNetIAMPermissionsForRolesResponse:      map[string][]string{},
			updatedFindings:                           []reflectFinding{},
			wantErr:                                   true,
		},
		{
			name: "getExistingTableSuccess#5",
			args: args{
				[]Comments{},
			},
			initFindings: []reflectFinding{},
			flags:        NewReflectFlags("us-east-1", []string{"arn:aws:iam::111111111111:role/AWS_111111111111_Read"}, map[string]string{}, true, true, false, "", 1),
			mockedGetS3LogPrefixForCloudTrailResponse: aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
			mockedGetS3LogPrefixForCloudTrailError:    nil,
			mockedGetTableforMetadataResponse:         aws.String("default.reflect_cloudtrail_gxev4"),
			mockedGetTableforMetadataError:            nil,
			mockedCreateTableFromMetadataResponse:     nil,
			mockedCreateTableFromMetadataError:        nil,
			GetRolesFromTagsResponse:                  nil,
			GetRolesFromTagsError:                     nil,
			mockedUsageReportRunQueryResponse:         athenaResultSetUsage,
			mockedErrorReportRunQueryResponse:         athenaResultSetError,
			mockedUsageReportRunQueryError:            nil,
			mockedErrorReportRunQueryError:            nil,
			GetNetIAMPermissionsForRolesResponse:      map[string][]string{},
			updatedFindings: []reflectFinding{
				{
					AccountID: "111111111111",
					Identity:  "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
					AccessDetails: []accessDetails{
						{"iam.amazonaws.com/UpdateAssumeRolePolicy", 1},
						{"iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied", 1},
					},
					PermissionSet: nil,
					Comments:      "NEW_FINDING",
				},
			},
			wantErr: false,
		},
		{
			name: "roleFromTagsSuccess#6",
			args: args{
				[]Comments{},
			},
			initFindings: []reflectFinding{},
			flags:        NewReflectFlags("us-east-1", nil, map[string]string{"myapp": "awesome"}, true, true, false, "", 1),
			mockedGetS3LogPrefixForCloudTrailResponse: aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
			mockedGetS3LogPrefixForCloudTrailError:    nil,
			mockedGetTableforMetadataResponse:         nil,
			mockedGetTableforMetadataError:            nil,
			mockedCreateTableFromMetadataResponse:     aws.String("default.reflect_cloudtrail_gxev4"),
			mockedCreateTableFromMetadataError:        nil,
			GetRolesFromTagsResponse:                  []string{"arn:aws:iam::111111111111:role/AWS_111111111111_Read"},
			GetRolesFromTagsError:                     nil,
			mockedUsageReportRunQueryResponse:         athenaResultSetUsage,
			mockedErrorReportRunQueryResponse:         athenaResultSetError,
			mockedUsageReportRunQueryError:            nil,
			mockedErrorReportRunQueryError:            nil,
			GetNetIAMPermissionsForRolesResponse:      map[string][]string{"arn:aws:iam::111111111111:role/AWS_111111111111_Read": {"iam:UpdateAssumeRolePolicy", "s3:GetObject"}},
			updatedFindings: []reflectFinding{
				{
					AccountID: "111111111111",
					Identity:  "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
					AccessDetails: []accessDetails{
						{"iam.amazonaws.com/UpdateAssumeRolePolicy", 1},
						{"iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied", 1},
					},
					PermissionSet: []string{"iam:UpdateAssumeRolePolicy", "s3:GetObject"},
					Comments:      "NEW_FINDING",
				},
			},
			wantErr: false,
		},
		{
			name: "allRoles#7",
			args: args{
				[]Comments{},
			},
			initFindings: []reflectFinding{},
			flags:        NewReflectFlags("us-east-1", nil, nil, true, true, false, "", 1),
			mockedGetS3LogPrefixForCloudTrailResponse: aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
			mockedGetS3LogPrefixForCloudTrailError:    nil,
			mockedGetTableforMetadataResponse:         nil,
			mockedGetTableforMetadataError:            nil,
			mockedCreateTableFromMetadataResponse:     aws.String("default.reflect_cloudtrail_gxev4"),
			mockedCreateTableFromMetadataError:        nil,
			GetRolesFromTagsResponse:                  nil,
			GetRolesFromTagsError:                     nil,
			mockedUsageReportRunQueryResponse:         athenaResultSetUsage,
			mockedErrorReportRunQueryResponse:         athenaResultSetError,
			mockedUsageReportRunQueryError:            nil,
			mockedErrorReportRunQueryError:            nil,
			GetNetIAMPermissionsForRolesResponse:      map[string][]string{"arn:aws:iam::111111111111:role/AWS_111111111111_Read": {"iam:UpdateAssumeRolePolicy", "s3:GetObject"}},
			updatedFindings: []reflectFinding{
				{
					AccountID: "111111111111",
					Identity:  "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
					AccessDetails: []accessDetails{
						{"iam.amazonaws.com/UpdateAssumeRolePolicy", 1},
						{"iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied", 1},
					},
					PermissionSet: []string{"iam:UpdateAssumeRolePolicy", "s3:GetObject"},
					Comments:      "NEW_FINDING",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ReflectReport{
				Findings: tt.initFindings,
				Flags:    tt.flags,
			}
			logger.Level = 1
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockAPI := mocks.NewMockAPIs(mockCtrl)
			mockAPI.EXPECT().GetAccountID().Return("111111111111", nil)
			mockAPI.EXPECT().GetS3LogPrefixForCloudTrail().Return(tt.mockedGetS3LogPrefixForCloudTrailResponse, tt.mockedGetS3LogPrefixForCloudTrailError)
			mockAPI.EXPECT().GetTableforMetadata(gomock.Any()).Return(tt.mockedGetTableforMetadataResponse, tt.mockedGetTableforMetadataError).AnyTimes()
			mockAPI.EXPECT().CreateTableFromMetadata(gomock.Any()).Return(tt.mockedCreateTableFromMetadataResponse, tt.mockedCreateTableFromMetadataError).AnyTimes()
			mockAPI.EXPECT().GetRolesFromTags(gomock.Any()).Return(tt.GetRolesFromTagsResponse, tt.GetRolesFromTagsError).AnyTimes()
			if tt.flags.usageReport {
				mockAPI.EXPECT().RunQuery(gomock.Any(), gomock.Any()).Return(tt.mockedUsageReportRunQueryResponse, tt.mockedUsageReportRunQueryError).MaxTimes(1)
			}

			if tt.flags.errorReport {
				mockAPI.EXPECT().RunQuery(gomock.Any(), gomock.Any()).Return(tt.mockedErrorReportRunQueryResponse, tt.mockedErrorReportRunQueryError).MaxTimes(1)
			}
			mockAPI.EXPECT().GetNetIAMPermissionsForRoles(gomock.Any()).Return(tt.GetNetIAMPermissionsForRolesResponse).AnyTimes()

			if err := report.GetReport(mockAPI, tt.args.comments); (err != nil) != tt.wantErr {
				t.Errorf("ReflectReport.GetReport() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(report.Findings, tt.updatedFindings) {
				t.Errorf("ReflectReport.GetReport() = %#v, want %#v", report.Findings, tt.updatedFindings)
			}
		})
	}
}

func TestReflectReport_populateFindings(t *testing.T) {

	type args struct {
		tableName string
	}
	tests := []struct {
		name                              string
		args                              args
		initFindings                      []reflectFinding
		flags                             ReflectFlags
		mockedUsageReportRunQueryResponse *athena.ResultSet
		mockedErrorReportRunQueryResponse *athena.ResultSet
		mockedUsageReportRunQueryError    error
		mockedErrorReportRunQueryError    error
		updatedFindings                   []reflectFinding
		wantErr                           bool
	}{
		{
			name:         "noData#1",
			args:         args{"default.reflect_cloudTrail_test1"},
			initFindings: []reflectFinding{},
			flags: ReflectFlags{
				usageReport: true,
				errorReport: true,
			},
			mockedUsageReportRunQueryResponse: &athena.ResultSet{},
			mockedErrorReportRunQueryResponse: &athena.ResultSet{},
			mockedUsageReportRunQueryError:    nil,
			mockedErrorReportRunQueryError:    nil,
			updatedFindings:                   []reflectFinding{},
			wantErr:                           false,
		},
		{
			name:         "runQueryError#2",
			args:         args{"default.reflect_cloudTrail_test1"},
			initFindings: []reflectFinding{},
			flags: ReflectFlags{
				usageReport: true,
				errorReport: true,
			},
			mockedUsageReportRunQueryResponse: &athena.ResultSet{},
			mockedErrorReportRunQueryResponse: &athena.ResultSet{},
			mockedUsageReportRunQueryError:    errors.New("some error"),
			mockedErrorReportRunQueryError:    nil,
			updatedFindings:                   []reflectFinding{},
			wantErr:                           true,
		},
		{
			name:         "dataFromBothQueries#3",
			args:         args{"default.reflect_cloudTrail_test1"},
			initFindings: []reflectFinding{},
			flags: ReflectFlags{
				usageReport: true,
				errorReport: true,
			},
			mockedUsageReportRunQueryResponse: &athena.ResultSet{
				ResultSetMetadata: &athena.ResultSetMetadata{ColumnInfo: []*athena.ColumnInfo{
					{
						Name: aws.String("arn"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("eventsource"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("eventname"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("count"),
						Type: aws.String("varchar"),
					},
				}},
				Rows: []*athena.Row{
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn")},
							{VarCharValue: aws.String("eventsource")},
							{VarCharValue: aws.String("eventname")},
							{VarCharValue: aws.String("count")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass")},
							{VarCharValue: aws.String("sts.amazonaws.com")},
							{VarCharValue: aws.String("AssumeRole")},
							{VarCharValue: aws.String("15")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/AWS_111111111111_Read")},
							{VarCharValue: aws.String("iam.amazonaws.com")},
							{VarCharValue: aws.String("UpdateAssumeRolePolicy")},
							{VarCharValue: aws.String("1")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/configuration-recorder-role")},
							{VarCharValue: aws.String("kms.amazonaws.com")},
							{VarCharValue: aws.String("DescribeKey")},
							{VarCharValue: aws.String("6")},
						},
					},
				},
			},
			mockedErrorReportRunQueryResponse: &athena.ResultSet{
				ResultSetMetadata: &athena.ResultSetMetadata{ColumnInfo: []*athena.ColumnInfo{
					{
						Name: aws.String("arn"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("eventsource"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("eventname"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("errorcode"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("count"),
						Type: aws.String("varchar"),
					},
				}},
				Rows: []*athena.Row{
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn")},
							{VarCharValue: aws.String("eventsource")},
							{VarCharValue: aws.String("eventname")},
							{VarCharValue: aws.String("errorcode")},
							{VarCharValue: aws.String("count")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass")},
							{VarCharValue: aws.String("sts.amazonaws.com")},
							{VarCharValue: aws.String("AssumeRole")},
							{VarCharValue: aws.String("AccessDenied")},
							{VarCharValue: aws.String("15")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/AWS_111111111111_Read")},
							{VarCharValue: aws.String("iam.amazonaws.com")},
							{VarCharValue: aws.String("UpdateAssumeRolePolicy")},
							{VarCharValue: aws.String("AccessDenied")},
							{VarCharValue: aws.String("1")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/configuration-recorder-role")},
							{VarCharValue: aws.String("kms.amazonaws.com")},
							{VarCharValue: aws.String("DescribeKey")},
							{VarCharValue: aws.String("AccessDenied")},
							{VarCharValue: aws.String("6")},
						},
					},
				},
			},
			mockedUsageReportRunQueryError: nil,
			mockedErrorReportRunQueryError: nil,
			updatedFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass",
					AccessDetails: []accessDetails{
						{"sts.amazonaws.com/AssumeRole", 15},
						{"sts.amazonaws.com/AssumeRole/AccessDenied", 15},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
					AccessDetails: []accessDetails{
						{"iam.amazonaws.com/UpdateAssumeRolePolicy", 1},
						{"iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied", 1},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/configuration-recorder-role",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey", 6},
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 6},
					},
				},
			},
			wantErr: false,
		},
		{
			name:         "dataFromErrorQuery#4",
			args:         args{"default.reflect_cloudTrail_test1"},
			initFindings: []reflectFinding{},
			flags: ReflectFlags{
				usageReport: false,
				errorReport: true,
			},
			mockedUsageReportRunQueryResponse: &athena.ResultSet{},
			mockedErrorReportRunQueryResponse: &athena.ResultSet{
				ResultSetMetadata: &athena.ResultSetMetadata{ColumnInfo: []*athena.ColumnInfo{
					{
						Name: aws.String("arn"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("eventsource"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("eventname"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("errorcode"),
						Type: aws.String("varchar"),
					},
					{
						Name: aws.String("count"),
						Type: aws.String("varchar"),
					},
				}},
				Rows: []*athena.Row{
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn")},
							{VarCharValue: aws.String("eventsource")},
							{VarCharValue: aws.String("eventname")},
							{VarCharValue: aws.String("errorcode")},
							{VarCharValue: aws.String("count")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass")},
							{VarCharValue: aws.String("sts.amazonaws.com")},
							{VarCharValue: aws.String("AssumeRole")},
							{VarCharValue: aws.String("AccessDenied")},
							{VarCharValue: aws.String("15")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/AWS_111111111111_Read")},
							{VarCharValue: aws.String("iam.amazonaws.com")},
							{VarCharValue: aws.String("UpdateAssumeRolePolicy")},
							{VarCharValue: aws.String("AccessDenied")},
							{VarCharValue: aws.String("1")},
						},
					},
					{
						Data: []*athena.Datum{
							{VarCharValue: aws.String("arn:aws:iam::111111111111:role/configuration-recorder-role")},
							{VarCharValue: aws.String("kms.amazonaws.com")},
							{VarCharValue: aws.String("DescribeKey")},
							{VarCharValue: aws.String("AccessDenied")},
							{VarCharValue: aws.String("6")},
						},
					},
				},
			},
			mockedUsageReportRunQueryError: nil,
			mockedErrorReportRunQueryError: nil,
			updatedFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass",
					AccessDetails: []accessDetails{
						{"sts.amazonaws.com/AssumeRole/AccessDenied", 15},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/AWS_111111111111_Read",
					AccessDetails: []accessDetails{
						{"iam.amazonaws.com/UpdateAssumeRolePolicy/AccessDenied", 1},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/configuration-recorder-role",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 6},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ReflectReport{
				Findings: tt.initFindings,
				Flags:    tt.flags,
			}
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockAPI := mocks.NewMockAPIs(mockCtrl)
			if tt.flags.usageReport {
				mockAPI.EXPECT().RunQuery(gomock.Any(), gomock.Any()).Return(tt.mockedUsageReportRunQueryResponse, tt.mockedUsageReportRunQueryError)
			}

			if tt.flags.errorReport {
				mockAPI.EXPECT().RunQuery(gomock.Any(), gomock.Any()).Return(tt.mockedErrorReportRunQueryResponse, tt.mockedErrorReportRunQueryError).AnyTimes()
			}

			findings, err := populateFindings(mockAPI, tt.args.tableName, report.Flags)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReflectReport.populateFindings() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(findings, tt.updatedFindings) {
				t.Errorf("ReflectReport.populateFindings() = %v, want %v", findings, tt.updatedFindings)
			}
		})
	}
}

func TestReflectReport_updateFinding(t *testing.T) {
	type args struct {
		identity string
		eventD   accessDetails
	}
	tests := []struct {
		name            string
		args            args
		providedRoles   []string
		initFindings    []reflectFinding
		updatedFindings []reflectFinding
	}{
		{
			name: "simpleAdd#1",
			args: args{
				identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
				eventD:   accessDetails{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
			},
			initFindings: []reflectFinding{},
			updatedFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
					},
				},
			},
		},
		{
			name: "simpleUpdate#2",
			args: args{
				identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
				eventD:   accessDetails{"kms.amazonaws.com/CreateKey", 5},
			},
			initFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
					},
				},
			},
			updatedFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
			},
		},
		{
			name: "addNewIdentity#3",
			args: args{
				identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
				eventD:   accessDetails{"kms.amazonaws.com/Decrypt", 7},
			},
			initFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
			},
			updatedFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/Decrypt", 7},
					},
				},
			},
		},
		{
			name: "updateCount#4",
			args: args{
				identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
				eventD:   accessDetails{"kms.amazonaws.com/Decrypt", 13},
			},
			initFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/Decrypt", 7},
					},
				},
			},
			updatedFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/Decrypt", 20},
					},
				},
			},
		},
		{
			name: "filterRole#5",
			args: args{
				identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-stage",
				eventD:   accessDetails{"kms.amazonaws.com/Decrypt", 31},
			},
			providedRoles: []string{"arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer", "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev"},
			initFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/Decrypt", 7},
					},
				},
			},
			updatedFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/Decrypt", 7},
					},
				},
			},
		},
		{
			name: "filterRole#6",
			args: args{
				identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-stage",
				eventD:   accessDetails{"kms.amazonaws.com/Decrypt", 31},
			},
			providedRoles: []string{"arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer", "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev", "arn:aws:iam::111111111111:role/web-gateway-greencherry-stage"},
			initFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/Decrypt", 7},
					},
				},
			},
			updatedFindings: []reflectFinding{
				{
					Identity: "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
						{"kms.amazonaws.com/CreateKey", 5},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/Decrypt", 7},
					},
				},
				{
					Identity: "arn:aws:iam::111111111111:role/web-gateway-greencherry-stage",
					AccessDetails: []accessDetails{
						{"kms.amazonaws.com/Decrypt", 31},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ReflectReport{}
			report.Flags.roles = tt.providedRoles
			updateFinding(report.Flags, &tt.initFindings, tt.args.identity, tt.args.eventD)
			if !reflect.DeepEqual(tt.initFindings, tt.updatedFindings) {
				t.Errorf("updateFinding() = %v, want %v", tt.initFindings, tt.updatedFindings)
			}
		})
	}
}

func Test_constructFinding(t *testing.T) {
	type args struct {
		dataSlice []string
		keys      []string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 accessDetails
	}{
		{
			name: "withErrorCode#1",
			args: args{
				dataSlice: []string{"arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer", "kms.amazonaws.com", "DescribeKey", "AccessDenied", "18"},
				keys:      []string{"arn", "eventsource", "eventname", "errorcode", "count"},
			},
			want:  "arn:aws:iam::111111111111:role/AWSServiceRoleForAccessAnalyzer",
			want1: accessDetails{"kms.amazonaws.com/DescribeKey/AccessDenied", 18},
		},
		{
			name: "withOutErrorCode#2",
			args: args{
				dataSlice: []string{"arn:aws:iam::111111111111:role/AWSServiceRoleForAmazonInspector", "ec2.amazonaws.com", "DescribeVpnGateways", "1"},
				keys:      []string{"arn", "eventsource", "eventname", "count"},
			},
			want:  "arn:aws:iam::111111111111:role/AWSServiceRoleForAmazonInspector",
			want1: accessDetails{"ec2.amazonaws.com/DescribeVpnGateways", 1},
		},
		{
			name: "withIdentity#3",
			args: args{
				dataSlice: []string{"arn:aws:iam::111111111111:role/web-gateway-greencherry-dev", "arn:aws:sts::111111111111:assumed-role/web-gateway-greencherry-dev/aws-sdk-java-1606285491012", "kms.amazonaws.com", "Decrypt", "3"},
				keys:      []string{"arn", "identity_arn", "eventsource", "eventname", "count"},
			},
			want:  "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev@aws-sdk-java-1606285491012",
			want1: accessDetails{"kms.amazonaws.com/Decrypt", 3},
		},
		{
			name: "withIdentityAndErrorCode#4",
			args: args{
				dataSlice: []string{"arn:aws:iam::111111111111:role/web-gateway-greencherry-dev", "arn:aws:sts::111111111111:assumed-role/web-gateway-greencherry-dev/aws-sdk-java-1606285491012", "kms.amazonaws.com", "DescribeKey", "AccessDenied", "19"},
				keys:      []string{"arn", "identity_arn", "eventsource", "eventname", "errorcode", "count"},
			},
			want:  "arn:aws:iam::111111111111:role/web-gateway-greencherry-dev@aws-sdk-java-1606285491012",
			want1: accessDetails{"kms.amazonaws.com/DescribeKey/AccessDenied", 19},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := constructFinding(tt.args.dataSlice, tt.args.keys)
			if got != tt.want {
				t.Errorf("constructFinding() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("constructFinding() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_createQueryFromFlags(t *testing.T) {
	type args struct {
		flags     ReflectFlags
		tableName string
		queryType string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "queryUsage#1",
			args: args{
				flags: ReflectFlags{
					region:              "us-east-1",
					roles:               []string{"arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass"},
					roleTags:            map[string]string{},
					usageReport:         true,
					errorReport:         true,
					includeUserIdentity: true,
					absoluteTime:        "10/25/2020-10/31/2020",
					relativeTime:        0,
				},
				tableName: "default.reflect_cloudtrail_cf4zi",
				queryType: queryForUsage,
			},
			want: `
SELECT useridentity.sessioncontext.sessionissuer.arn,useridentity.arn AS identity_arn,eventsource,eventname,count(eventname) AS count
FROM default.reflect_cloudtrail_cf4zi
WHERE region='us-east-1'
    AND year IN ('2020')
	AND month IN ('10')
	AND day IN ('25','26','27','28','29','30','31')
	AND eventtime >= '2020-10-25T00:00:00Z'
	AND eventtime <= '2020-10-31T23:59:59Z'
	AND useridentity.sessioncontext.sessionissuer.arn LIKE 'arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass'
GROUP BY useridentity.arn,eventsource,eventname,useridentity.sessioncontext.sessionissuer.arn
ORDER BY useridentity.arn,count DESC
`,
		},
		{
			name: "queryError#2",
			args: args{
				flags: ReflectFlags{
					region:              "us-east-2",
					roles:               []string{"arn:aws:iam::111111111111:role/AWS_111111111111_BreakDoor"},
					roleTags:            map[string]string{},
					usageReport:         true,
					errorReport:         true,
					includeUserIdentity: false,
					absoluteTime:        "09/03/2020-11/12/2020",
					relativeTime:        0,
				},
				tableName: "default.reflect_cloudtrail_cf4zi",
				queryType: queryForErrors,
			},
			want: `
SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode,count(useridentity.sessioncontext.sessionissuer.arn) AS count
FROM default.reflect_cloudtrail_cf4zi
WHERE region='us-east-2'
    AND year IN ('2020')
    AND month IN ('09','10','11')
    AND day IN ('01','02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31')
	AND eventtime >= '2020-09-03T00:00:00Z'
	AND eventtime <= '2020-11-12T23:59:59Z'
	AND useridentity.arn != ''
	AND useridentity.sessioncontext.sessionissuer.arn LIKE 'arn:aws:iam::111111111111:role/AWS_111111111111_BreakDoor'
	AND (errorcode LIKE '%UnauthorizedOperation' OR errorcode LIKE 'AccessDenied%')
GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode
ORDER BY useridentity.arn,count DESC
`,
		},
		{
			name: "queryError#3",
			args: args{
				flags: ReflectFlags{
					region:       "us-east-1",
					roles:        []string{"arn:aws:iam::111111111111:role/AWS_111111111111_BreakDoor", "arn:aws:iam::111111111111:role/AWS_111111111111_BreakChair"},
					roleTags:     map[string]string{},
					usageReport:  true,
					errorReport:  true,
					absoluteTime: "03/03/2020-09/02/2020",
					relativeTime: 0,
				},
				tableName: "default.reflect_cloudtrail_cf4zi",
				queryType: queryForErrors,
			},
			want: `
SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode,count(useridentity.sessioncontext.sessionissuer.arn) AS count
FROM default.reflect_cloudtrail_cf4zi
WHERE region='us-east-1'
    AND year IN ('2020')
    AND month IN ('03','04','05','06','07','08','09')
    AND day IN ('01','02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31')
	AND eventtime >= '2020-03-03T00:00:00Z'
	AND eventtime <= '2020-09-02T23:59:59Z'
	AND useridentity.arn != ''
	AND (errorcode LIKE '%UnauthorizedOperation' OR errorcode LIKE 'AccessDenied%')
GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode
ORDER BY useridentity.arn,count DESC
`,
		},
		{
			name: "queryUsage#4",
			args: args{
				flags: ReflectFlags{
					region:       "us-east-2",
					roles:        []string{"arn:aws:iam::111111111111:role/AWS_111111111111_BreakGlass", "arn:aws:iam::111111111111:role/AWS_111111111111_BreakFan", "arn:aws:iam::111111111111:role/AWS_111111111111_BreakTV"},
					roleTags:     map[string]string{},
					usageReport:  true,
					errorReport:  true,
					absoluteTime: "10/25/2020-10/25/2020",
					relativeTime: 0,
				},
				tableName: "default.reflect_cloudtrail_cf4zi",
				queryType: queryForUsage,
			},
			want: `
SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,count(eventname) AS count
FROM default.reflect_cloudtrail_cf4zi
WHERE region='us-east-2'
    AND year IN ('2020')
	AND month IN ('10')
	AND day IN ('25')
	AND eventtime >= '2020-10-25T00:00:00Z'
	AND eventtime <= '2020-10-25T23:59:59Z'
GROUP BY useridentity.arn,eventsource,eventname,useridentity.sessioncontext.sessionissuer.arn
ORDER BY useridentity.arn,count DESC
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createQueryFromFlags(tt.args.flags, tt.args.tableName, tt.args.queryType); got != tt.want {
				t.Errorf("createQueryFromFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getAbsoluteTime(t *testing.T) {
	type args struct {
		timeRelative int
		now          time.Time
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "#1",
			args: args{
				timeRelative: 10,
				now:          time.Date(2020, time.November, 10, 23, 0, 0, 0, time.UTC),
			},
			want: "10/31/2020-11/10/2020",
		},
		{
			name: "#2",
			args: args{
				timeRelative: 0,
				now:          time.Date(2020, time.November, 10, 23, 0, 0, 0, time.UTC),
			},
			want: "11/10/2020-11/10/2020",
		},
		{
			name: "#3",
			args: args{
				timeRelative: 90,
				now:          time.Date(2020, time.November, 10, 23, 0, 0, 0, time.UTC),
			},
			want: "08/12/2020-11/10/2020",
		},
		{
			name: "#4",
			args: args{
				timeRelative: 370,
				now:          time.Date(2020, time.November, 10, 23, 0, 0, 0, time.UTC),
			},
			want: "11/06/2019-11/10/2020",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAbsoluteTime(tt.args.timeRelative, tt.args.now); got != tt.want {
				t.Errorf("getAbsoluteTime() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ConstructPartitionDataFromTime(t *testing.T) {
	testCases := []struct {
		name           string
		timeAbsolute   string
		expectedOutput timeRange
	}{
		{
			name:         "absoluteOnly#1",
			timeAbsolute: "10/01/2020-10/01/2020",
			expectedOutput: timeRange{
				Months:         []int{10},
				Days:           []int{1},
				Years:          []int{2020},
				EventTimeRange: []string{"2020-10-01T00:00:00Z", "2020-10-01T23:59:59Z"},
			},
		},
		{
			name:         "absoluteOnly#2",
			timeAbsolute: "10/02/2020-10/04/2020",
			expectedOutput: timeRange{
				Months:         []int{10},
				Days:           []int{2, 3, 4},
				Years:          []int{2020},
				EventTimeRange: []string{"2020-10-02T00:00:00Z", "2020-10-04T23:59:59Z"},
			},
		},
		{
			name:         "absoluteOnly#3",
			timeAbsolute: "10/09/2020-10/17/2020",
			expectedOutput: timeRange{
				Months:         []int{10},
				Days:           []int{9, 10, 11, 12, 13, 14, 15, 16, 17},
				Years:          []int{2020},
				EventTimeRange: []string{"2020-10-09T00:00:00Z", "2020-10-17T23:59:59Z"},
			},
		},
		{
			name:         "absoluteOnly#4",
			timeAbsolute: "10/01/2020-10/30/2020",
			expectedOutput: timeRange{
				Months:         []int{10},
				Days:           []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30},
				Years:          []int{2020},
				EventTimeRange: []string{"2020-10-01T00:00:00Z", "2020-10-30T23:59:59Z"},
			},
		},
		{
			name:         "absoluteOnly#5",
			timeAbsolute: "10/01/2020-11/30/2020",
			expectedOutput: timeRange{
				Months:         []int{10, 11},
				Days:           []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				Years:          []int{2020},
				EventTimeRange: []string{"2020-10-01T00:00:00Z", "2020-11-30T23:59:59Z"},
			},
		},
		{
			name:         "absoluteOnly#6",
			timeAbsolute: "10/06/2020-12/04/2020",
			expectedOutput: timeRange{
				Months:         []int{10, 11, 12},
				Days:           []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				Years:          []int{2020},
				EventTimeRange: []string{"2020-10-06T00:00:00Z", "2020-12-04T23:59:59Z"},
			},
		},
		{
			name:         "absolute#7",
			timeAbsolute: "10/01/2020-03/30/2021",
			expectedOutput: timeRange{
				Months:         []int{1, 2, 3, 10, 11, 12},
				Days:           []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				Years:          []int{2020, 2021},
				EventTimeRange: []string{"2020-10-01T00:00:00Z", "2021-03-30T23:59:59Z"},
			},
		},
		{
			name:         "absolute#8",
			timeAbsolute: "02/28/2019-09/14/2021",
			expectedOutput: timeRange{
				Months:         []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Days:           []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				Years:          []int{2019, 2020, 2021},
				EventTimeRange: []string{"2019-02-28T00:00:00Z", "2021-09-14T23:59:59Z"},
			},
		},
		{
			name:         "absolute#9",
			timeAbsolute: "10/17/2019-04/12/2020",
			expectedOutput: timeRange{
				Months:         []int{1, 2, 3, 4, 10, 11, 12},
				Days:           []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				Years:          []int{2019, 2020},
				EventTimeRange: []string{"2019-10-17T00:00:00Z", "2020-04-12T23:59:59Z"},
			},
		},
		{
			name:         "absolute#10",
			timeAbsolute: "10/04/2020-11/04/2020",
			expectedOutput: timeRange{
				Months:         []int{10, 11},
				Days:           []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				Years:          []int{2020},
				EventTimeRange: []string{"2020-10-04T00:00:00Z", "2020-11-04T23:59:59Z"},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := constructPartitionDataFromTime(tt.timeAbsolute); !reflect.DeepEqual(got, tt.expectedOutput) {
				t.Errorf("constructPartitionDataFromTime() = %v, want %v", got, tt.expectedOutput)
			}
		})
	}
}
