#!/bin/bash

yum install openscap-scanner scap-security-guide -y

if grep -q -i "Amazon Linux release 2" /etc/system-release ; then
  scriptFile="/usr/share/xml/scap/ssg/content/ssg-amzn2-ds.xml"
  sudo sed -i 's|https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml.bz2|https://www.redhat.com/security/data/oval/v2/RHEL7/rhel-7.oval.xml.bz2|g' "$scriptFile"
elif grep -q -i "release 8" /etc/redhat-release ; then
  scriptFile="/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml"
elif grep -q -i "release 7" /etc/redhat-release ; then
  scriptFile="/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml"
elif grep -q -i "release 6" /etc/redhat-release ; then
  scriptFile="/usr/share/xml/scap/ssg/content/ssg-rhel6-ds.xml"
else
  echo "Running neither AMZN2.x, RHEL6.x, RHEL7.x nor RHEL 8.x !"
fi

if [ "$scriptFile" ]; then
  sed -i 's/multi-check="true"/multi-check="false"/g' "$scriptFile"
  oscap xccdf eval --fetch-remote-resources --profile xccdf_org.ssgproject.content_profile_stig-rhel7-disa --results-arf arf.xml --report report.html "$scriptFile"
fi

instanceId=$(ec2-metadata -i | grep -o 'i-.*' | awk '{print $1}')
timestamp=$(date +%s)

aws s3 cp arf.xml s3://testingmarch2024testing/$instanceId/$timestamp-scap-results.xml
aws s3 cp report.html s3://testingmarch2024testing/$instanceId/$timestamp-scap-results.html