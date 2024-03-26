import json
import boto3
import datetime
from datetime import date
import xml.etree.ElementTree as ET

s3 = boto3.client('s3')
cloudWatch = boto3.client('cloudwatch')
dynamodb = boto3.resource('dynamodb')
securityHub = boto3.client('securityhub')
ssmClient = boto3.client('ssm')


def main():
    
    # get the bucket name so that we can get the file from s3
    bucket_name = "testingcftmarch2024"
    file_key = "scap-results.xml"
    aws_account_id = "344594102751"
    region = "us-east-1"
    
    #get the instance id from the s3 path
    instanceId = file_key.split('/')[0]
    
    # get the object
    obj = s3.get_object(Bucket=bucket_name, Key=file_key)
    
    # r = requests.get('https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V1R2_STIG.zip')

    # Get parameter for using Security Hub
    useSecurityHub = ssmClient.get_parameter(Name='/SCAPTesting/EnableSecurityHub')['Parameter']['Value']
    
    # parse the XML from s3
    root = ET.fromstring(obj['Body'].read())
    
    # get the resutls node from the xml
    testResult = root.find(".//{http://checklists.nist.gov/xccdf/1.2}TestResult")
    testVersion = testResult.attrib.get("version") 
    
    # setup counts for cloudwatch metrics
    high=0
    medium=0
    low=0
    unknown=0
    
    
    # load the ignore list from DynamoDB
    ignoreList = getIgnoreList()
    
    # setup arrays to hold the findings so we can do batch inserts
    dynamoDbItems = []
    securityHubFindings = []
    
    # iterate through each result item
    for item in testResult: 
        testId = str(item.attrib.get("idref"))

        # We need to normalize the rule name here to check agains the
        # ignore list
        if '.' in testId:
            testId = testId[testId.rindex('.')+1:len(testId)]

        # if we are not ignoring the result, them count it and store in DynamoDB
        if testId not in ignoreList:
            if(item.findtext('{http://checklists.nist.gov/xccdf/1.2}result') == "fail"):
                saveToDynamoDB(dynamoDbItems, instanceId, item, bucket_name, file_key)
                pushToSecurityHub(securityHubFindings,root, instanceId, item, region, aws_account_id, testVersion, bucket_name, file_key)
                # if useSecurityHub == "true" and item.attrib.get("severity") in ["high","medium","low"]:
                #     try:
                #         pushToSecurityHub(securityHubFindings,root, instanceId, item, region, aws_account_id, testVersion, bucket_name, file_key)
                #     except Exception as e:
                #         useSecurityHub = "false"
                #         print("SecurityHub is not enabled b: " + str(e))
                if(item.attrib.get("severity") == "high"):
                    high+=1
                elif(item.attrib.get("severity") == "medium"):
                    medium+=1
                elif(item.attrib.get("severity") == "low"):
                    low+=1
                elif(item.attrib.get("severity") == "unknown"):
                    unknown+=1
            
    # Send metrics to cloudwatch for alerting        
    sendMetic(high, 'SCAP High Finding', instanceId)
    sendMetic(medium, 'SCAP Medium Finding', instanceId)
    sendMetic(low, 'SCAP Low Finding', instanceId)
    # Batch write all findings to DynamoDB
    table = dynamodb.Table('SCAP_Scan_Results')
    with table.batch_writer() as batch:
        for item in dynamoDbItems:
            batch.put_item(
                Item = item
            )
    
    # if Security Hub is enabled, send the results in batches of 100
    if useSecurityHub == "true":
        myfindings = securityHubFindings
        try:
            findingsLeft = True
            startIndex = 0
            stopIndex = len(myfindings)

            # Loop through the findings sending 100 at a time to Security Hub
            while findingsLeft:
                stopIndex = startIndex + 100
                if stopIndex > len(securityHubFindings):
                    stopIndex = len(securityHubFindings)
                    findingsLeft = False
                else:
                    stopIndex = 100
                myfindings = securityHubFindings[startIndex:stopIndex]
                # submit the finding to Security Hub
                result = securityHub.batch_import_findings(Findings = myfindings)
                startIndex = startIndex + 100

                # print results to CloudWatch
                print(result)
        except Exception as e:
            print("SecurityHub is not enabled a: " + str(e))
            

# Saves the results to DynamoDB   
def saveToDynamoDB(dynamoDbItems, instanceId, item, bucket_name, file_key):
    #table = dynamodb.Table('SCAP_Scan_Results')
    #table.put_item(
    dynamoDbItems.append({
            'InstanceId': instanceId,
            'SCAP_Rule_Name': item.attrib.get("idref"),
            'time': item.attrib.get("time"), 
            'severity':  item.attrib.get("severity"),
            'result': item.findtext('{http://checklists.nist.gov/xccdf/1.2}result'),
            'report_url': 's3://'+ bucket_name + "/" + file_key.replace('.xml', '.html')
            }
    )


# method for creating the metrics
def sendMetic(value, title, instanceId):
    cloudWatch.put_metric_data(
        Namespace='Compliance',
        MetricData=[
            {
                'MetricName': title,
                'Dimensions': [
                    {
                        'Name': 'InstanceId',
                        'Value': instanceId
                    },
                ],
                'Value': value
            }
        ]
    )

# fetches the ignore list from DynamoDB    
def getIgnoreList():
    table = dynamodb.Table('SCAP_Scan_Ignore_List')
    #if you list is really long this could fail as it will pagonate
    response = table.scan()
    list = response['Items']
    returnList = []
    for item in list:
        returnList.append(item['SCAP_Rule_Name'])
    return returnList
    
def pushToSecurityHub(securityHubFindings, root, instanceId, item, region, aws_account_id, testVersion, bucket_name, file_key):
    rule = root.find(".//{http://checklists.nist.gov/xccdf/1.2}Rule[@id='" + item.attrib.get("idref") + "']")
    profile = root.find('.//{http://checklists.nist.gov/xccdf/1.2}Profile[@id="xccdf_org.ssgproject.content_profile_stig"]')

    # fix the time format from OpenSCAP to Security Hub
    time = item.attrib.get("time")
    if time.find('+') != -1:
        time = time[:time.rindex('+')]
    time =  time + ".000Z"
    
    securityHubFindings.append(
            {
                'SchemaVersion': '2018-10-08',
                'Id': item.attrib.get("idref") + "_" + file_key,
                'ProductArn': 'arn:aws:securityhub:' + region + ':'+ aws_account_id +':product/' + aws_account_id + '/default',
                'GeneratorId': 'OpenSCAP ' + item.attrib.get("idref"),
                'AwsAccountId': aws_account_id,
                'Types': [
                    'Software and Configuration Checks',
                ],
                'FirstObservedAt': time,
                'LastObservedAt': time,
                'CreatedAt': time,
                'UpdatedAt': time,
                'Severity': {
                    'Label': item.attrib.get("severity").upper()
                },
                'Title': rule.findtext('{http://checklists.nist.gov/xccdf/1.2}title'),
                'Description': str(rule.findtext('{http://checklists.nist.gov/xccdf/1.2}description')) + " ",
                'Remediation': {
                    'Recommendation': {
                        'Text': 'For remediation please see: s3://'+ bucket_name + '/' + file_key.replace('.xml', '.html')
                    }
                },
                'ProductFields': {
                    "ProviderName": str(rule.findtext('{http://checklists.nist.gov/xccdf/1.2}title')) + " ",
                    "ProviderVersion": testVersion
                },
                'Resources': [
                    {
                        'Type': 'AwsEc2Instance',
                        'Id': instanceId,
                        'Region': region
                    },
                ],
                'Compliance': {
                    'Status': 'FAILED'
                },
                'WorkflowState': 'NEW',
                'Workflow': {
                    'Status': 'NEW'
                }
            })
    
if __name__ == "__main__":
    main()