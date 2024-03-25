import json
import boto3
import datetime
import requests
import os
import logging
from datetime import date
import xml.etree.ElementTree as ET



logger = logging.getLogger(__name__)
logger.setLevel("INFO")

def download_s3_object(bucket_name, object_key, local_filename):
    s3 = boto3.client('s3')
    s3.download_file(bucket_name, object_key, local_filename)

def main():

    bucket_name = 'testingcftmarch2024'
    object_key = 'scap-results.xml'
    local_filename = 'scap-results.xml'

    download_s3_object(bucket_name, object_key, local_filename)

    file_path = os.path.abspath(local_filename)
    with open(file_path, 'rb') as file:
        root = ET.fromstring(file.read())

    testResult = root.find(".//{http://checklists.nist.gov/xccdf/1.2}TestResult")
    logger.info(type(testResult))
    logger.info(testResult)
    testVersion = testResult.attrib.get("version")
    print(testResult)
    print(testVersion)

if __name__ == "__main__":
    main()