package aws

import (
	"context"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Optum/cloudig/pkg/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/golang/mock/gomock"
)

var (
	regionList []string
)

func TestMain(m *testing.M) {
	for _, p := range endpoints.DefaultPartitions() {
		for region := range p.Regions() {
			regionList = append(regionList, region)
		}
	}

	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestClient_GetTableforMetadata(t *testing.T) {
	// 	sess, _ := NewAuthenticatedSession("us-east-1")
	// 	meta := NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail")
	// 	tableName, err := NewClient(sess).GetTableforMetadata(meta)
	// 	if err != nil {
	// 		log.Println(err)
	// 	}
	// 	log.Println(aws.StringValue(tableName))
	// 	t.Fail()
	type args struct {
		meta *athena.TableMetadata
	}

	tests := []struct {
		name                            string
		args                            args
		mockedListDataCatalogsResponse  *athena.ListDataCatalogsOutput
		mockedListDatabasesResponse     *athena.ListDatabasesOutput
		mockedListTableMetadataResponse *athena.ListTableMetadataOutput
		mockedListTableMetadataErr      error
		want                            *string
		wantErr                         bool
	}{
		{
			name: "getTablesuccessful#1",
			args: args{NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList)},
			mockedListDataCatalogsResponse: &athena.ListDataCatalogsOutput{DataCatalogsSummary: []*athena.DataCatalogSummary{
				{CatalogName: aws.String("AwsDataCatalog"), Type: aws.String("GLUE")},
			}},
			mockedListDatabasesResponse: &athena.ListDatabasesOutput{DatabaseList: []*athena.Database{
				{Name: aws.String("default")},
				{Name: aws.String("testDB")},
				{Name: aws.String("simpleDB")},
			}},
			mockedListTableMetadataResponse: &athena.ListTableMetadataOutput{TableMetadataList: []*athena.TableMetadata{
				{
					Name: aws.String("reflect_test"),
					Columns: []*athena.Column{
						{
							Name: aws.String("additionaleventdata"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("apiversion"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("awsregion"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("errorcode"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("errormessage"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventname"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventsource"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventtime"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventtype"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventversion"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("readonly"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("recipientaccountid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("requestid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("requestparameters"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("resources"),
							Type: aws.String("array<struct<ARN:string,accountId:string,type:string>>"),
						}, {
							Name: aws.String("responseelements"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("serviceeventdetails"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("sharedeventid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("sourceipaddress"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("useragent"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("useridentity"),
							Type: aws.String("struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,userName:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalId:string,arn:string,accountId:string,userName:string>>>"),
						}, {
							Name: aws.String("vpcendpointid"),
							Type: aws.String("string"),
						},
					},
					Parameters: map[string]*string{
						"serde.serialization.lib":   aws.String("com.amazon.emr.hive.serde.CloudTrailSerde"),
						"inputformat":               aws.String("com.amazon.emr.cloudtrail.CloudTrailInputFormat"),
						"outputformat":              aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
						"location":                  aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
						"projection.enabled":        aws.String("true"),
						"projection.region.type":    aws.String("enum"),
						"projection.region.values":  aws.String(strings.Join(regionList, ",")),
						"projection.year.type":      aws.String("integer"),
						"projection.year.range":     aws.String("2005,2099"),
						"projection.month.type":     aws.String("integer"),
						"projection.month.range":    aws.String("1,12"),
						"projection.month.digits":   aws.String("2"),
						"projection.day.type":       aws.String("integer"),
						"projection.day.range":      aws.String("1,31"),
						"projection.day.digits":     aws.String("2"),
						"storage.location.template": aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail" + "/${region}/${year}/${month}/${day}"),
					},
					PartitionKeys: []*athena.Column{
						{
							Name: aws.String("day"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("month"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("region"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("year"),
							Type: aws.String("string"),
						},
					},
				},
			}},
			want:    aws.String("default.reflect_test"),
			wantErr: false,
		},
		{
			name: "missingColumns#2",
			args: args{NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList)},
			mockedListDataCatalogsResponse: &athena.ListDataCatalogsOutput{DataCatalogsSummary: []*athena.DataCatalogSummary{
				{CatalogName: aws.String("AwsDataCatalog"), Type: aws.String("GLUE")},
			}},
			mockedListDatabasesResponse: &athena.ListDatabasesOutput{DatabaseList: []*athena.Database{
				{Name: aws.String("default")},
			}},
			mockedListTableMetadataResponse: &athena.ListTableMetadataOutput{TableMetadataList: []*athena.TableMetadata{
				{
					Name: aws.String("reflect_table"),
					Columns: []*athena.Column{
						{
							Name: aws.String("readonly"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("recipientaccountid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("requestid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("requestparameters"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("resources"),
							Type: aws.String("array<struct<ARN:string,accountId:string,type:string>>"),
						}, {
							Name: aws.String("responseelements"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("serviceeventdetails"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("sharedeventid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("sourceipaddress"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("useragent"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("useridentity"),
							Type: aws.String("struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,userName:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalId:string,arn:string,accountId:string,userName:string>>>"),
						}, {
							Name: aws.String("vpcendpointid"),
							Type: aws.String("string"),
						},
					},
					Parameters: map[string]*string{
						"serde.serialization.lib":   aws.String("com.amazon.emr.hive.serde.CloudTrailSerde"),
						"inputformat":               aws.String("com.amazon.emr.cloudtrail.CloudTrailInputFormat"),
						"outputformat":              aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
						"location":                  aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
						"projection.enabled":        aws.String("true"),
						"projection.region.type":    aws.String("enum"),
						"projection.region.values":  aws.String("us-east-1,us-east-2,us-west-1,us-west-2"),
						"projection.year.type":      aws.String("integer"),
						"projection.year.range":     aws.String("2005,2099"),
						"projection.month.type":     aws.String("integer"),
						"projection.month.range":    aws.String("1,12"),
						"projection.month.digits":   aws.String("2"),
						"projection.day.type":       aws.String("integer"),
						"projection.day.range":      aws.String("1,31"),
						"projection.day.digits":     aws.String("2"),
						"storage.location.template": aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail" + "/${region}/${year}/${month}/${day}"),
					},
					PartitionKeys: []*athena.Column{
						{
							Name: aws.String("day"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("month"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("region"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("year"),
							Type: aws.String("string"),
						},
					},
				},
			}},
			want:    nil,
			wantErr: false,
		},
		{
			name: "missingParameters#3",
			args: args{NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList)},
			mockedListDataCatalogsResponse: &athena.ListDataCatalogsOutput{DataCatalogsSummary: []*athena.DataCatalogSummary{
				{CatalogName: aws.String("AwsDataCatalog"), Type: aws.String("GLUE")},
			}},
			mockedListDatabasesResponse: &athena.ListDatabasesOutput{DatabaseList: []*athena.Database{
				{Name: aws.String("default")},
				{Name: aws.String("testDB")},
				{Name: aws.String("simpleDB")},
			}},
			mockedListTableMetadataResponse: &athena.ListTableMetadataOutput{TableMetadataList: []*athena.TableMetadata{
				{
					Name: aws.String("reflect_test"),
					Columns: []*athena.Column{
						{
							Name: aws.String("additionaleventdata"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("apiversion"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("awsregion"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("errorcode"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("errormessage"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventname"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventsource"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventtime"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventtype"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("eventversion"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("readonly"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("recipientaccountid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("requestid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("requestparameters"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("resources"),
							Type: aws.String("array<struct<ARN:string,accountId:string,type:string>>"),
						}, {
							Name: aws.String("responseelements"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("serviceeventdetails"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("sharedeventid"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("sourceipaddress"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("useragent"),
							Type: aws.String("string"),
						}, {
							Name: aws.String("useridentity"),
							Type: aws.String("struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,userName:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalId:string,arn:string,accountId:string,userName:string>>>"),
						}, {
							Name: aws.String("vpcendpointid"),
							Type: aws.String("string"),
						},
					},
					Parameters: map[string]*string{
						"serde.serialization.lib":   aws.String("com.amazon.emr.hive.serde.CloudTrailSerde"),
						"inputformat":               aws.String("com.amazon.emr.cloudtrail.CloudTrailInputFormat"),
						"outputformat":              aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
						"location":                  aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail"),
						"projection.enabled":        aws.String("true"),
						"projection.region.type":    aws.String("enum"),
						"projection.month.digits":   aws.String("2"),
						"projection.day.type":       aws.String("integer"),
						"projection.day.range":      aws.String("1,31"),
						"projection.day.digits":     aws.String("2"),
						"storage.location.template": aws.String("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail" + "/${region}/${year}/${month}/${day}"),
					},
					PartitionKeys: []*athena.Column{
						{
							Name: aws.String("day"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("month"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("region"),
							Type: aws.String("string"),
						},
						{
							Name: aws.String("year"),
							Type: aws.String("string"),
						},
					},
				},
			}},
			want:    nil,
			wantErr: false,
		},
		{
			name: "errorFromListTableMetData#4",
			args: args{NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList)},
			mockedListDataCatalogsResponse: &athena.ListDataCatalogsOutput{DataCatalogsSummary: []*athena.DataCatalogSummary{
				{CatalogName: aws.String("AwsDataCatalog"), Type: aws.String("GLUE")},
			}},
			mockedListDatabasesResponse: &athena.ListDatabasesOutput{DatabaseList: []*athena.Database{
				{Name: aws.String("default")},
				{Name: aws.String("testDB")},
				{Name: aws.String("simpleDB")},
			}},
			mockedListTableMetadataResponse: &athena.ListTableMetadataOutput{},
			mockedListTableMetadataErr:      errors.New("some error"),
			want:                            nil,
			wantErr:                         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockAthenaAPI := mocks.NewMockAthenaAPI(mockCtrl)
			mockAthenaAPI.EXPECT().ListDataCatalogs(&athena.ListDataCatalogsInput{}).Return(tt.mockedListDataCatalogsResponse, nil)
			for _, v := range tt.mockedListDataCatalogsResponse.DataCatalogsSummary {
				mockAthenaAPI.EXPECT().ListDatabases(&athena.ListDatabasesInput{CatalogName: v.CatalogName}).Return(tt.mockedListDatabasesResponse, nil).AnyTimes()
				for _, v1 := range tt.mockedListDatabasesResponse.DatabaseList {
					mockAthenaAPI.EXPECT().ListTableMetadata(&athena.ListTableMetadataInput{CatalogName: v.CatalogName, DatabaseName: v1.Name}).Return(tt.mockedListTableMetadataResponse, tt.mockedListTableMetadataErr).AnyTimes()
				}
			}
			client := &Client{
				Athena: mockAthenaAPI,
			}
			got, err := client.GetTableforMetadata(tt.args.meta)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetTableforMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				if tt.want != nil {
					t.Errorf("Client.GetTableforMetadata() = %v, want %v", got, tt.want)
				}
			} else if *got != *tt.want {
				t.Errorf("Client.GetTableforMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_CreateTableFromMetadata(t *testing.T) {
	// 	sess, _ := NewAuthenticatedSession("us-east-1")
	// 	meta := NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail")
	// 	tableName, err := NewClient(sess).CreateTableFromMetadata(meta)
	// 	if err != nil {
	// 		log.Println(err)
	// 	}
	// 	log.Println(aws.StringValue(tableName))
	// 	t.Fail()
	meta := NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList)
	metaBadLocation := NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList).
		SetParameters(map[string]*string{}).
		SetPartitionKeys([]*athena.Column{})
	somePointerToString := aws.String("testmenomore")
	type args struct {
		meta *athena.TableMetadata
	}
	tests := []struct {
		name                                         string
		args                                         args
		mockedStartQueryExecutionWithContextResponse *athena.StartQueryExecutionOutput
		mockedGetQueryExecutionResponse              *athena.GetQueryExecutionOutput
		match                                        bool
		wantErr                                      bool
	}{
		{
			name: "createTableSuccess#1",
			args: args{meta: meta},
			mockedStartQueryExecutionWithContextResponse: &athena.StartQueryExecutionOutput{
				QueryExecutionId: somePointerToString,
			},
			mockedGetQueryExecutionResponse: &athena.GetQueryExecutionOutput{
				QueryExecution: &athena.QueryExecution{
					Status: &athena.QueryExecutionStatus{State: aws.String(athena.QueryExecutionStateSucceeded)},
				},
			},
			match:   true,
			wantErr: false,
		},
		{
			name: "badQueryData#2",
			args: args{meta: metaBadLocation},
			mockedStartQueryExecutionWithContextResponse: &athena.StartQueryExecutionOutput{
				QueryExecutionId: somePointerToString,
			},
			mockedGetQueryExecutionResponse: &athena.GetQueryExecutionOutput{
				QueryExecution: &athena.QueryExecution{
					Status: &athena.QueryExecutionStatus{State: aws.String(athena.QueryExecutionStateFailed)},
				},
			},
			match:   false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockAthenaAPI := mocks.NewMockAthenaAPI(mockCtrl)
			// https://github.com/golang/mock/issues/324
			mockAthenaAPI.EXPECT().StartQueryExecutionWithContext(context.Background(), gomock.Any(), gomock.Any()).Return(tt.mockedStartQueryExecutionWithContextResponse, nil)
			mockAthenaAPI.EXPECT().GetQueryExecution(&athena.GetQueryExecutionInput{
				QueryExecutionId: tt.mockedStartQueryExecutionWithContextResponse.QueryExecutionId,
			}).Return(tt.mockedGetQueryExecutionResponse, nil).AnyTimes()
			client := &Client{
				Athena: mockAthenaAPI,
			}
			got, err := client.CreateTableFromMetadata(tt.args.meta)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.CreateTableFromMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			regexMatch, _ := regexp.MatchString("default.reflect_cloudTrail_[A-Za-z0-9]{5}$", aws.StringValue(got))
			if tt.match != regexMatch {
				t.Errorf("Client.CreateTableFromMetadata() got = %v, doesn't match '%v'", aws.StringValue(got), "default.reflect_cloudTrail_[A-Za-z0-9]{5}$")
			}
		})
	}
}

func TestClient_RunQuery(t *testing.T) {
	// 	sess, _ := NewAuthenticatedSession("us-east-1")
	// 	query1 :=
	// 		`SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode,count(useridentity.sessioncontext.sessionissuer.arn) AS count
	// 	FROM default.reflect_cloudtrail_gxev4
	// 	WHERE region='us-east-1'
	// 		AND year IN ('2020')
	// 		AND month IN ('11')
	// 		AND day IN ('14','15','16','17','18','19','20','21')
	// 		AND eventtime >= '2020-11-14T00:00:00Z'
	// 		AND eventtime <= '2020-11-21T23:59:59Z'
	// 		AND useridentity.arn != ''
	// 		AND (errorcode LIKE '%UnauthorizedOperation' OR errorcode LIKE 'AccessDenied%')
	// 	GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode
	// 	ORDER BY useridentity.arn,count DESC`

	// 	result, err := NewClient(sess).RunQuery("default.reflect_cloudtrail_gxev4", query1)
	// 	if err != nil {
	// 		log.Println(err)
	// 		t.Fail()
	// 	}
	// 	//log.Println(result.ResultSetMetadata.ColumnInfo)
	// 	// data := make(map[string]string)
	// 	// dataSet := make([]map[string]string, 0)
	// 	// keys := make([]string, 0)
	// 	// //values := make([]string, 0)
	// 	// for k, v := range result.Rows {
	// 	// 	if k == 0 {
	// 	// 		for _, v1 := range v.Data {
	// 	// 			keys = append(keys, aws.StringValue(v1.VarCharValue))
	// 	// 		}
	// 	// 		continue
	// 	// 	}
	// 	// 	for k2, v2 := range v.Data {
	// 	// 		data[keys[k2]] = aws.StringValue(v2.VarCharValue)
	// 	// 	}
	// 	// 	dataSet = append(dataSet, data)
	// 	// 	//log.Println(v.GoString())
	// 	// }
	// 	// log.Println(dataSet)
	// 	table := tablewriter.NewWriter(os.Stdout)
	// 	table.SetRowLine(true)
	// 	table.SetRowSeparator("-")
	// 	keys := make([]string, 0)
	// 	values := make([]string, 0)
	// 	for k, v := range result.Rows {
	// 		if k == 0 {
	// 			for _, v1 := range v.Data {
	// 				keys = append(keys, aws.StringValue(v1.VarCharValue))
	// 			}
	// 			table.SetHeader(keys)
	// 			continue
	// 		}
	// 		for _, v2 := range v.Data {
	// 			values = append(values, aws.StringValue(v2.VarCharValue))
	// 		}
	// 		table.Append(values)
	// 		values = nil
	// 	}
	// 	table.Render()
	// 	t.Fail()
	meta := NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList)
	somePointerToString := aws.String("testmenomore")
	resultSet := &athena.ResultSet{
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
	}

	type args struct {
		tableName string
		query     string
	}
	tests := []struct {
		name                                         string
		args                                         args
		mockedGetTableMetadataResponse               *athena.GetTableMetadataOutput
		mockedStartQueryExecutionWithContextResponse *athena.StartQueryExecutionOutput
		mockedGetQueryExecutionResponse              *athena.GetQueryExecutionOutput
		mockedGetQueryResultsWithContextResponse     *athena.GetQueryResultsOutput
		want                                         *athena.ResultSet
		wantErr                                      bool
	}{
		{
			name: "runQuerySuccess#1",
			args: args{
				"default.reflect_test",
				`SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode,count(useridentity.sessioncontext.sessionissuer.arn) AS count
                 FROM default.reflect_test
                 WHERE region='us-east-1'
                 	AND year IN ('2020')
                 	AND month IN ('11')
                 	AND day IN ('14','15','16','17','18','19','20','21')
                 	AND eventtime >= '2020-11-14T00:00:00Z'
                 	AND eventtime <= '2020-11-21T23:59:59Z'
                 	AND useridentity.arn != ''
                 	AND (errorcode LIKE '%UnauthorizedOperation' OR errorcode LIKE 'AccessDenied%')
                 GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode
                 ORDER BY useridentity.arn,count DESC`,
			},
			mockedGetTableMetadataResponse: &athena.GetTableMetadataOutput{
				TableMetadata: meta,
			},
			mockedStartQueryExecutionWithContextResponse: &athena.StartQueryExecutionOutput{
				QueryExecutionId: somePointerToString,
			},
			mockedGetQueryExecutionResponse: &athena.GetQueryExecutionOutput{
				QueryExecution: &athena.QueryExecution{
					Status: &athena.QueryExecutionStatus{State: aws.String(athena.QueryExecutionStateSucceeded)},
				},
			},
			mockedGetQueryResultsWithContextResponse: &athena.GetQueryResultsOutput{ResultSet: resultSet},
			want:                                     resultSet,
			wantErr:                                  false,
		},
		{
			name: "QueryFailure#2",
			args: args{
				"default.reflect_test",
				`SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode,count(useridentity.sessioncontext.sessionissuer.arn) AS count
                 FROM default.reflect_test
                 WHERE region='us-east-1'
                 	AND year IN ('2020')
                 	AND month IN ('11')
                 	AND day IN ('14','15','16','17','18','19','20','21')
                 	AND eventtime >= '2020-11-14T00:00:00Z'
                 	AND eventtime <= '2020-11-21T23:59:59Z'
                 	AND useridentity.arn != ''
                 	AND (errorcode LIKE '%UnauthorizedOperation' OR errorcode LIKE 'AccessDenied%')
                 GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode
                 ORDER BY useridentity.arn,count DESC`,
			},
			mockedGetTableMetadataResponse: &athena.GetTableMetadataOutput{
				TableMetadata: meta,
			},
			mockedStartQueryExecutionWithContextResponse: &athena.StartQueryExecutionOutput{
				QueryExecutionId: somePointerToString,
			},
			mockedGetQueryExecutionResponse: &athena.GetQueryExecutionOutput{
				QueryExecution: &athena.QueryExecution{
					Status: &athena.QueryExecutionStatus{State: aws.String(athena.QueryExecutionStateFailed)},
				},
			},
			mockedGetQueryResultsWithContextResponse: &athena.GetQueryResultsOutput{ResultSet: nil},
			want:                                     nil,
			wantErr:                                  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockAthenaAPI := mocks.NewMockAthenaAPI(mockCtrl)
			mockAthenaAPI.EXPECT().GetTableMetadata(gomock.Any()).Return(tt.mockedGetTableMetadataResponse, nil)
			mockAthenaAPI.EXPECT().StartQueryExecutionWithContext(context.Background(), gomock.Any(), gomock.Any()).Return(tt.mockedStartQueryExecutionWithContextResponse, nil)
			mockAthenaAPI.EXPECT().GetQueryExecution(&athena.GetQueryExecutionInput{
				QueryExecutionId: tt.mockedStartQueryExecutionWithContextResponse.QueryExecutionId,
			}).Return(tt.mockedGetQueryExecutionResponse, nil).AnyTimes()
			mockAthenaAPI.EXPECT().GetQueryResultsWithContext(context.Background(), &athena.GetQueryResultsInput{
				QueryExecutionId: aws.String("testmenomore"),
			}, gomock.Any()).Return(tt.mockedGetQueryResultsWithContextResponse, nil).AnyTimes()
			client := &Client{
				Athena: mockAthenaAPI,
			}
			got, err := client.RunQuery(tt.args.tableName, tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.RunQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Client.RunQuery() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_runQueryToCompletion(t *testing.T) {
	somePointerToString := aws.String("testmenomore")
	type args struct {
		meta    *athena.TableMetadata
		query   string
		timeout time.Duration
	}
	tests := []struct {
		name                                         string
		args                                         args
		mockedStartQueryExecutionWithContextResponse *athena.StartQueryExecutionOutput
		mockedGetQueryExecutionResponse              *athena.GetQueryExecutionOutput
		want                                         *string
		wantErr                                      bool
	}{
		{
			name: "executionStateSucceeded#1",
			args: args{
				NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList),
				`SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode,count(useridentity.sessioncontext.sessionissuer.arn) AS count
				FROM default.reflect_cloudtrail_gxev4
				WHERE region='us-east-1'
					AND year IN ('2020')
					AND month IN ('11')
					AND day IN ('14','15','16','17','18','19','20','21')
					AND eventtime >= '2020-11-14T00:00:00Z'
					AND eventtime <= '2020-11-21T23:59:59Z'
					AND useridentity.arn != ''
					AND (errorcode LIKE '%UnauthorizedOperation' OR errorcode LIKE 'AccessDenied%')
				GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode
				ORDER BY useridentity.arn,count DESC`,
				60,
			},
			mockedStartQueryExecutionWithContextResponse: &athena.StartQueryExecutionOutput{
				QueryExecutionId: somePointerToString,
			},
			mockedGetQueryExecutionResponse: &athena.GetQueryExecutionOutput{
				QueryExecution: &athena.QueryExecution{
					Status: &athena.QueryExecutionStatus{State: aws.String(athena.QueryExecutionStateSucceeded)},
				},
			},
			want:    somePointerToString,
			wantErr: false,
		},
		{
			name: "executionStateFailed#2",
			args: args{
				NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList),
				`SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode,count(useridentity.sessioncontext.sessionissuer.arn) AS count
				FROM default.reflect_cloudtrail_gxev4
				WHERE region='us-east-1'
					AND year IN ('2020')
					AND month IN ('11')
					AND day IN ('14','15','16','17','18','19','20','21')
					AND eventtime >= '2020-11-14T00:00:00Z'
					AND eventtime <= '2020-11-21T23:59:59Z'
					AND useridentity.arn != ''
					AND (errorcode LIKE '%UnauthorizedOperation' OR errorcode LIKE 'AccessDenied%')
				GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode
				ORDER BY useridentity.arn,count DESC`,
				30,
			},
			mockedStartQueryExecutionWithContextResponse: &athena.StartQueryExecutionOutput{
				QueryExecutionId: somePointerToString,
			},
			mockedGetQueryExecutionResponse: &athena.GetQueryExecutionOutput{
				QueryExecution: &athena.QueryExecution{
					Status: &athena.QueryExecutionStatus{State: aws.String(athena.QueryExecutionStateFailed)},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "executionTimeout#3",
			args: args{
				NewAthenaTableMetaDataForCloudTrail("s3://lp-cl-111111111111-us-east-1/source=aws/account=111111111111/region=us-east-1/env=prod/aggregation=cloudtrail/service=cloudtrail/AWSLogs/111111111111/CloudTrail", regionList),
				`SELECT useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode,count(useridentity.sessioncontext.sessionissuer.arn) AS count
				FROM default.reflect_cloudtrail_gxev4
				WHERE region='us-east-1'
					AND year IN ('2020')
					AND month IN ('11')
					AND day IN ('14','15','16','17','18','19','20','21')
					AND eventtime >= '2020-11-14T00:00:00Z'
					AND eventtime <= '2020-11-21T23:59:59Z'
					AND useridentity.arn != ''
					AND (errorcode LIKE '%UnauthorizedOperation' OR errorcode LIKE 'AccessDenied%')
				GROUP BY useridentity.arn,useridentity.sessioncontext.sessionissuer.arn,eventsource,eventname,errorcode
				ORDER BY useridentity.arn,count DESC`,
				5,
			},
			mockedStartQueryExecutionWithContextResponse: &athena.StartQueryExecutionOutput{
				QueryExecutionId: somePointerToString,
			},
			mockedGetQueryExecutionResponse: &athena.GetQueryExecutionOutput{
				QueryExecution: &athena.QueryExecution{
					Status: &athena.QueryExecutionStatus{State: aws.String(athena.QueryExecutionStateRunning)},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockAthenaAPI := mocks.NewMockAthenaAPI(mockCtrl)
			ctx := context.Background()
			input := &athena.StartQueryExecutionInput{
				QueryExecutionContext: &athena.QueryExecutionContext{
					Catalog:  aws.String(defaultCatalog),
					Database: aws.String(defaultDatabase),
				},
				ResultConfiguration: &athena.ResultConfiguration{
					OutputLocation: aws.String(aws.StringValue(tt.args.meta.Parameters["location"]) + "/athenaQueryResults/"),
				},
				QueryString: aws.String(tt.args.query),
			}
			// https://github.com/golang/mock/issues/324
			mockAthenaAPI.EXPECT().StartQueryExecutionWithContext(ctx, input, gomock.Any()).Return(tt.mockedStartQueryExecutionWithContextResponse, nil)
			mockAthenaAPI.EXPECT().GetQueryExecution(&athena.GetQueryExecutionInput{
				QueryExecutionId: tt.mockedStartQueryExecutionWithContextResponse.QueryExecutionId,
			}).Return(tt.mockedGetQueryExecutionResponse, nil).AnyTimes()
			mockAthenaAPI.EXPECT().StopQueryExecution(gomock.Any()).Return(&athena.StopQueryExecutionOutput{}, nil).AnyTimes()
			client := &Client{
				Athena: mockAthenaAPI,
			}
			got, err := client.runQueryToCompletion(tt.args.meta, tt.args.query, tt.args.timeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.runQueryToCompletion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Client.runQueryToCompletion() = %v, want %v", got, tt.want)
			}
		})
	}
}
