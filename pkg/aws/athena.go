package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/dchest/uniuri"
)

// AthenaSVC is a wrapper for Athena service API calls
type AthenaSVC interface {
	GetTableforMetadata(*athena.TableMetadata) (*string, error)
	CreateTableFromMetadata(*athena.TableMetadata) (*string, error)
	RunQuery(tableName, query string) (*athena.ResultSet, error)
	GetTableMetadata(string) (*athena.TableMetadata, error)
}

const (
	createTableTimeout time.Duration = 30  // in seconds
	runQueryTimeout    time.Duration = 900 // in seconds
	readTimeout        time.Duration = 10  // in seconds
	iterationSleepTime time.Duration = 5   // in seconds
	defaultDatabase    string        = "default"
	defaultCatalog     string        = "AwsDataCatalog"
)

// NewAthenaTableMetaDataForCloudTrail creates the metadata for CloudTrail table
// Returned metadata will not have Name for the table or location of the datasource
// Note : Sorted by value of Name
func NewAthenaTableMetaDataForCloudTrail(location string, regionList []string) *athena.TableMetadata {
	cloudTrailAthenaTableColumns := []*athena.Column{
		{
			Name: aws.String("additionaleventdata"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("apiversion"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("awsregion"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("errorcode"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("errormessage"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("eventid"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("eventname"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("eventsource"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("eventtime"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("eventtype"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("eventversion"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("readonly"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("recipientaccountid"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("requestid"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("requestparameters"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("resources"),
			Type: aws.String("array<struct<ARN:string,accountId:string,type:string>>"),
		},
		{
			Name: aws.String("responseelements"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("serviceeventdetails"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("sharedeventid"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("sourceipaddress"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("useragent"),
			Type: aws.String("string"),
		},
		{
			Name: aws.String("useridentity"),
			Type: aws.String("struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,userName:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalId:string,arn:string,accountId:string,userName:string>>>"),
		},
		{
			Name: aws.String("vpcendpointid"),
			Type: aws.String("string"),
		},
	}

	// Note : Sorted by value of Name
	// TODO : customizable partitions
	cloudTrailAthenaTablePartitions := []*athena.Column{
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
	}

	cloudTrailAthenaTableParameters := map[string]*string{
		"serde.serialization.lib":   aws.String("com.amazon.emr.hive.serde.CloudTrailSerde"),
		"inputformat":               aws.String("com.amazon.emr.cloudtrail.CloudTrailInputFormat"),
		"outputformat":              aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
		"location":                  aws.String(location),
		"projection.enabled":        aws.String("true"), // TODO : customizable partition projections
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
		"storage.location.template": aws.String(location + "/${region}/${year}/${month}/${day}"),
	}

	return &athena.TableMetadata{
		Columns:       cloudTrailAthenaTableColumns,
		PartitionKeys: cloudTrailAthenaTablePartitions,
		Parameters:    cloudTrailAthenaTableParameters,
		TableType:     aws.String("EXTERNAL_TABLE"),
	}
}

// represents the dataset used to form a query to create table
type tableCreateData struct {
	TableName                     string
	Columns                       map[string]string
	Partitions                    map[string]string
	Parameters                    map[string]string
	PartitionProjectionParameters map[string]string
}

// getDataToCreateTable helper function that creates the struct from the given Athena table metadata
// this struct is used by the template engine to generate the query
func getDataToCreateTable(meta *athena.TableMetadata) *tableCreateData {
	columns := make(map[string]string)
	for _, v := range meta.Columns {
		columns[aws.StringValue(v.Name)] = aws.StringValue(v.Type)
	}
	partitions := make(map[string]string)
	for _, v := range meta.PartitionKeys {
		partitions[aws.StringValue(v.Name)] = aws.StringValue(v.Type)
	}

	parameters := make(map[string]string)
	partitionParameters := make(map[string]string)
	for k, v := range meta.Parameters {
		if strings.HasPrefix(k, "projection.") || strings.HasPrefix(k, "storage.location.template") {
			partitionParameters[k] = aws.StringValue(v)
		} else {
			parameters[k] = aws.StringValue(v)
		}
	}

	tableName := defaultDatabase + "." + "reflect_cloudTrail_" + uniuri.NewLen(5)

	return &tableCreateData{
		TableName:                     tableName,
		Columns:                       columns,
		Partitions:                    partitions,
		Parameters:                    parameters,
		PartitionProjectionParameters: partitionParameters,
	}
}

// GetTableforMetadata returns a Athena table in the form <databasename>.<tablename> for given metadata and
// an error if there is any. Region is derived from authenticated session
func (client *Client) GetTableforMetadata(meta *athena.TableMetadata) (*string, error) {
	resultCatalogs, err := client.Athena.ListDataCatalogs(&athena.ListDataCatalogsInput{})
	if err != nil {
		return nil, err
	}
	if len(resultCatalogs.DataCatalogsSummary) > 0 {
		for _, catalogSummary := range resultCatalogs.DataCatalogsSummary {
			resultDatabases, err := client.Athena.ListDatabases(&athena.ListDatabasesInput{
				CatalogName: catalogSummary.CatalogName,
			})
			if err != nil {
				return nil, err
			}
			if len(resultDatabases.DatabaseList) > 0 {
				for _, database := range resultDatabases.DatabaseList {
					resultTable, err := client.Athena.ListTableMetadata(
						&athena.ListTableMetadataInput{
							CatalogName:  catalogSummary.CatalogName,
							DatabaseName: database.Name,
						})
					if err != nil {
						return nil, err
					}
					if len(resultTable.TableMetadataList) > 0 {
						for _, tableMeta := range resultTable.TableMetadataList {
							// check "location" key is present before accessing it
							if val, ok := tableMeta.Parameters["location"]; ok {
								// lets first find the table by comparing the location parameter
								if aws.StringValue(val) == aws.StringValue(meta.Parameters["location"]) {

									// compare partition key matches
									if !reflect.DeepEqual(meta.PartitionKeys, tableMeta.PartitionKeys) {
										continue
									}
									// compare Columns matches
									if !reflect.DeepEqual(meta.Columns, tableMeta.Columns) {
										continue
									}

									// compare all other parameters matches
									totalParams := len(meta.Parameters)
									checkedParams := 0
									for pk, pv := range meta.Parameters {
										if val, ok := tableMeta.Parameters[pk]; ok {
											if aws.StringValue(val) != aws.StringValue(pv) {
												break
											}
										} else {
											break
										}
										checkedParams++
									}
									if checkedParams == totalParams {
										return aws.String(aws.StringValue(database.Name) + "." + aws.StringValue(tableMeta.Name)), nil
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return nil, nil
}

// CreateTableFromMetadata creates a Athena Table for given metadata and returns a table name in the form <databasename>.<tablename>
// and an error if there is any. Region is derived from authenticated session
func (client *Client) CreateTableFromMetadata(meta *athena.TableMetadata) (*string, error) {
	queryData := getDataToCreateTable(meta)
	/*
		CREATE [EXTERNAL] TABLE [IF NOT EXISTS]
		 [db_name.]table_name [(col_name data_type [COMMENT col_comment] [, ...] )]
		 [COMMENT table_comment]
		 [PARTITIONED BY (col_name data_type [COMMENT col_comment], ...)]
		 [ROW FORMAT row_format]
		 [STORED AS file_format]
		 [WITH SERDEPROPERTIES (...)] ]
		 [LOCATION 's3://bucket_name/[folder]/']
		 [TBLPROPERTIES ( ['has_encrypted_data'='true | false',] ['classification'='aws_glue_classification',] property_name=property_value [, ...] ) ]
	*/
	queryString := `
	CREATE EXTERNAL TABLE {{.TableName}} ({{$first := true}}{{range $key, $value := .Columns}}{{if $first}} {{$first = false}}{{else}},{{end}}
	 {{$key}} {{$value}}{{end}}
	)
	PARTITIONED BY ( {{$first := true}}{{range $key, $value := .Partitions}}{{if $first}} {{$first = false}}{{else}},{{end}}
     {{$key}} {{$value}}{{end}}
	)
	ROW FORMAT SERDE '{{index .Parameters "serde.serialization.lib"}}'
	STORED AS INPUTFORMAT '{{index .Parameters "inputformat"}}'
	OUTPUTFORMAT '{{index .Parameters "outputformat"}}'
	LOCATION '{{index .Parameters "location"}}'
	TBLPROPERTIES({{$first := true}}{{range $key, $value := .PartitionProjectionParameters}}{{if $first}} {{$first = false}}{{else}},{{end}}
		"{{$key}}" = "{{$value}}"{{end}}
	)
	`
	t := template.Must(template.New("query").Parse(queryString))
	var tpl bytes.Buffer
	err := t.Execute(&tpl, queryData)
	if err != nil {
		return nil, err
	}
	_, err = client.runQueryToCompletion(meta, tpl.String(), createTableTimeout)
	if err != nil {
		return nil, err
	}
	return &queryData.TableName, nil
}

// RunQuery run the give query on the given table and returns the data and an error if there is any
func (client *Client) RunQuery(tableName, query string) (*athena.ResultSet, error) {
	meta, err := client.GetTableMetadata(tableName)
	if err != nil {
		return nil, err
	}

	id, err := client.runQueryToCompletion(meta, query, runQueryTimeout)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	queryOutput, err := client.Athena.GetQueryResultsWithContext(
		ctx,
		&athena.GetQueryResultsInput{QueryExecutionId: id},
		request.WithResponseReadTimeout(readTimeout*time.Second),
	)
	if err != nil {
		return nil, err
	}
	resultSSMeta := queryOutput.ResultSet.ResultSetMetadata
	resultSSRows := queryOutput.ResultSet.Rows
	token := queryOutput.NextToken
	for token != nil {
		queryOutput, err := client.Athena.GetQueryResultsWithContext(
			ctx,
			&athena.GetQueryResultsInput{
				QueryExecutionId: id,
				NextToken:        token,
			}, request.WithResponseReadTimeout(readTimeout*time.Second),
		)
		if err != nil {
			return nil, err
		}
		resultSSRows = append(resultSSRows, queryOutput.ResultSet.Rows...)
		token = queryOutput.NextToken
	}
	return &athena.ResultSet{ResultSetMetadata: resultSSMeta, Rows: resultSSRows}, nil
}

// runQueryToCompletion run the given query on the table derived from the metadata and returns a QueryExecutionId
// when the query is successful within the given timeout(in sec) and an error if the query is not successful
func (client *Client) runQueryToCompletion(meta *athena.TableMetadata, query string, timeout time.Duration) (*string, error) {
	input := &athena.StartQueryExecutionInput{
		QueryExecutionContext: &athena.QueryExecutionContext{
			Catalog:  aws.String(defaultCatalog),
			Database: aws.String(defaultDatabase),
		},
		ResultConfiguration: &athena.ResultConfiguration{
			// results are saved in the same bucket where the datasource is
			OutputLocation: aws.String(aws.StringValue(meta.Parameters["location"]) + "/athenaQueryResults/"),
		},
		QueryString: aws.String(query),
	}
	ctx := context.Background()
	resp, err := client.Athena.StartQueryExecutionWithContext(ctx, input, request.WithResponseReadTimeout(readTimeout*time.Second))
	if err != nil {
		return nil, err
	}
	retryLimit := 1
	limit := int(timeout / iterationSleepTime)
	if limit > 0 {
		retryLimit = limit
	}
	for i := 0; i < retryLimit; i++ {
		result, err := client.Athena.GetQueryExecution(&athena.GetQueryExecutionInput{QueryExecutionId: resp.QueryExecutionId})
		if err != nil {
			return nil, err
		}
		status := aws.StringValue(result.QueryExecution.Status.State)
		if status == athena.QueryExecutionStateSucceeded {
			return resp.QueryExecutionId, nil
		}

		if status == athena.QueryExecutionStateFailed || status == athena.QueryExecutionStateCancelled {
			return nil, fmt.Errorf("Error while running the query. Reason: %s", aws.StringValue(result.QueryExecution.Status.StateChangeReason))
		}

		time.Sleep(iterationSleepTime * time.Second)
	}

	// control reaches here only if table creation status is not successful before the Timeout
	_, _ = client.Athena.StopQueryExecution(&athena.StopQueryExecutionInput{QueryExecutionId: resp.QueryExecutionId})
	return nil, errors.New("timeout while running the query")
}

// GetTableMetadata is helper function to return the athena table metadata for given table
func (client *Client) GetTableMetadata(tableName string) (*athena.TableMetadata, error) {
	table := strings.Split(tableName, ".")
	input := &athena.GetTableMetadataInput{
		CatalogName:  aws.String(defaultCatalog),
		DatabaseName: aws.String(table[0]),
		TableName:    aws.String(table[1]),
	}
	result, err := client.Athena.GetTableMetadata(input)
	if err != nil {
		return nil, err
	}
	return result.TableMetadata, nil
}
