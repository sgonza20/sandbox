package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

var (
	s3Client         *s3.S3
	cloudWatchClient *cloudwatch.CloudWatch
	dynamoDBClient   *dynamodb.DynamoDB
	securityHubClient *securityhub.SecurityHub
	ssmClient        ssmiface.SSMAPI
)

func init() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	s3Client = s3.New(sess)
	cloudWatchClient = cloudwatch.New(sess)
	dynamoDBClient = dynamodb.New(sess)
	securityHubClient = securityhub.New(sess)
	ssmClient = ssm.New(sess)
}

func lambdaHandler(ctx context.Context, event events.S3Event) error {
	bucketName := event.Records[0].S3.Bucket.Name
	fileKey := event.Records[0].S3.Object.Key
	awsAccountID := strings.Split(ctx.InvokedFunctionArn, ":")[4]
	region := strings.Split(ctx.InvokedFunctionArn, ":")[3]

	instanceID := strings.Split(fileKey, "/")[0]

	obj, err := s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(fileKey),
	})
	if err != nil {
		return err
	}

	useSecurityHub, err := getParameter("/SCAPTesting/EnableSecurityHub")
	if err != nil {
		return err
	}

	root := ET.fromstring(obj.Body)
	testResult := root.find(".//{http://checklists.nist.gov/xccdf/1.2}TestResult")
	testVersion := testResult.Attr["version"]

	high, medium, low, unknown := 0, 0, 0, 0

	ignoreList, err := getIgnoreList()
	if err != nil {
		return err
	}

	var dynamoDBItems []map[string]*dynamodb.AttributeValue
	var securityHubFindings []*securityhub.AWSSecurityFinding

	for _, item := range testResult {
		testID := item.Attr["idref"]
		if strings.Contains(testID, ".") {
			testID = testID[strings.LastIndex(testID, ".")+1:]
		}

		if !contains(ignoreList, testID) {
			if item.Find(".//{http://checklists.nist.gov/xccdf/1.2}result").Text() == "fail" {
				saveToDynamoDB(&dynamoDBItems, instanceID, item, bucketName, fileKey)
				if useSecurityHub == "yes" && contains([]string{"high", "medium", "low"}, item.Attr["severity"]) {
					err := pushToSecurityHub(&securityHubFindings, root, instanceID, item, region, awsAccountID, testVersion, bucketName, fileKey)
					if err != nil {
						useSecurityHub = "no"
						fmt.Printf("SecurityHub is not enabled b: %v\n", err)
					}
				}
				switch item.Attr["severity"] {
				case "high":
					high++
				case "medium":
					medium++
				case "low":
					low++
				case "unknown":
					unknown++
				}
			}
		}
	}

	sendMetric(high, "SCAP High Finding", instanceID)
	sendMetric(medium, "SCAP Medium Finding", instanceID)
	sendMetric(low, "SCAP Low Finding", instanceID)

	batchWriteToDynamoDB(&dynamoDBItems)

	if useSecurityHub == "yes" {
		err := batchSubmitToSecurityHub(securityHubFindings)
		if err != nil {
			fmt.Printf("SecurityHub is not enabled a: %v\n", err)
		}
	}

	return nil
}

func saveToDynamoDB(dynamoDBItems *[]map[string]*dynamodb.AttributeValue, instanceID, item, bucketName, fileKey string) {
	dynamoDBItems = append(dynamoDBItems, map[string]*dynamodb.AttributeValue{
		"InstanceId":      {S: aws.String(instanceID)},
		"SCAP_Rule_Name":  {S: aws.String(item.Attr["idref"])},
		"time":            {S: aws.String(item.Attr["time"])},
		"severity":        {S: aws.String(item.Attr["severity"])},
		"result":          {S: aws.String(item.Find(".//{http://checklists.nist.gov/xccdf/1.2}result").Text())},
		"report_url":      {S: aws.String(fmt.Sprintf("s3://%s/%s", bucketName, strings.ReplaceAll(fileKey, ".xml", ".html")))},
	})
}

func sendMetric(value int, title, instanceID string) {
	_, err := cloudWatchClient.PutMetricData(&cloudwatch.PutMetricDataInput{
		Namespace: aws.String("Compliance"),
		MetricData: []*cloudwatch.MetricDatum{
			{
				MetricName: aws.String(title),
				Dimensions: []*cloudwatch.Dimension{
					{
						Name:  aws.String("InstanceId"),
						Value: aws.String(instanceID),
					},
				},
				Value: aws.Float64(float64(value)),
			},
		},
	})
	if err != nil {
		fmt.Printf("Error sending metric: %v\n", err)
	}
}

func getIgnoreList() ([]string, error) {
	input := &dynamodb.ScanInput{
		TableName: aws.String("SCAP_Scan_Ignore_List"),
	}
	result, err := dynamoDBClient.Scan(input)
	if err != nil {
		return nil, err
	}
	var ignoreList []string
	for _, item := range result.Items {
		ignoreList = append(ignoreList, aws.StringValue(item["SCAP_Rule_Name"].S))
	}
	return ignoreList, nil
}

func pushToSecurityHub(securityHubFindings *[]*securityhub.AWSSecurityFinding, root *ET.Element, instanceID, item, region, awsAccountID, testVersion, bucketName, fileKey string) error {
	rule := root.Find(fmt.Sprintf(".//{http://checklists.nist.gov/xccdf/1.2}Rule[@id='%s']", item.Attr["idref"]))
	profile := root.Find(".//{http://checklists.nist.gov/xccdf/1.2}Profile[@id='xccdf_org.ssgproject.content_profile_stig']")

	timeStr := item.Attr["time"]
	if strings.Index(timeStr, "+") != -1 {
		timeStr = timeStr[:strings.LastIndex(timeStr, "+")]
	}
	timeStr += ".000Z"

	*securityHubFindings = append(*securityHubFindings, &securityhub.AWSSecurityFinding{
		SchemaVersion: aws.String("2018-10-08"),
		Id:            aws.String(item.Attr["idref"] + "_" + fileKey),
		ProductArn:    aws.String(fmt.Sprintf("arn:aws:securityhub:%s:%s:product/%s/default", region, awsAccountID, awsAccountID)),
		GeneratorId:   aws.String(fmt.Sprintf("OpenSCAP %s", item.Attr["idref"])),
		AwsAccountId:  aws.String(awsAccountID),
		Types: []*string{
			aws.String("Software and Configuration Checks"),
		},
		FirstObservedAt: aws.String(timeStr),
		LastObservedAt:  aws.String(timeStr),
		CreatedAt:       aws.String(timeStr),
		UpdatedAt:       aws.String(timeStr),
		Severity: &securityhub.Severity{
			Label: aws.String(strings.ToUpper(item.Attr["severity"])),
		},
		Title: aws.String(rule.Find(".//{http://checklists.nist.gov/xccdf/1.2}title").Text()),
		Description: aws.String(fmt.Sprintf("%s ", rule.Find(".//{http://checklists.nist.gov/xccdf/1.2}description").Text())),
		Remediation: &securityhub.Remediation{
			Recommendation: &securityhub.Recommendation{
				Text: aws.String(fmt.Sprintf("For remediation please see: s3://%s/%s", bucketName, strings.ReplaceAll(fileKey, ".xml", ".html"))),
			},
		},
		ProductFields: map[string]*string{
			"ProviderName":    aws.String(profile.Find(".//{http://checklists.nist.gov/xccdf/1.2}title").Text()),
			"ProviderVersion": aws.String(testVersion),
		},
		Resources: []*securityhub.Resource{
			{
				Type:   aws.String("AwsEc2Instance"),
				Id:     aws.String(instanceID),
				Region: aws.String(region),
			},
		},
		Compliance: &securityhub.Compliance{
			Status: aws.String("FAILED"),
		},
		WorkflowState: aws.String("NEW"),
		Workflow: &securityhub.Workflow{
			Status: aws.String("NEW"),
		},
	})
}
}

func getParameter(paramName string) (string, error) {
input := &ssm.GetParameterInput{
	Name:           aws.String(paramName),
	WithDecryption: aws.Bool(true),
}
result, err := ssmClient.GetParameter(input)
if err != nil {
	return "", err
}
return aws.StringValue(result.Parameter.Value), nil
}

func contains(s []string, e string) bool {
for _, a := range s {
	if a == e {
		return true
	}
}
return false
}

func batchWriteToDynamoDB(items *[]map[string]*dynamodb.AttributeValue) {
tableName := "SCAP_Scan_Results"
writeRequests := make([]*dynamodb.WriteRequest, len(*items))
for i, item := range *items {
	writeRequests[i] = &dynamodb.WriteRequest{
		PutRequest: &dynamodb.PutRequest{
			Item: item,
		},
	}
}

batchRequest := &dynamodb.BatchWriteItemInput{
	RequestItems: map[string][]*dynamodb.WriteRequest{
		tableName: writeRequests,
	},
}

dynamoDBClient.BatchWriteItem(batchRequest)
}

func batchSubmitToSecurityHub(findings []*securityhub.AWSSecurityFinding) error {
batchSize := 100
for i := 0; i < len(findings); i += batchSize {
	end := i + batchSize
	if end > len(findings) {
		end = len(findings)
	}
	chunk := findings[i:end]

	batchRequest := &securityhub.BatchImportFindingsInput{
		Findings: chunk,
	}

	_, err := securityHubClient.BatchImportFindings(batchRequest)
	if err != nil {
		return err
	}
}
return nil
}

func main() {
lambda.Start(lambdaHandler)
}
