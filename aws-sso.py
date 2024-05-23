#!/usr/bin/python3

# AWS SSO CLI implementation for login flows and CLI caching available 
# here https://github.com/boto/botocore/blob/v2/botocore/utils.py
# and here: https://github.com/aws/aws-cli/blob/v2/awscli/customizations/sso/utils.py

import boto3
import os
from os import system, name 
from pathlib import Path
import json
import datetime
import time
import configparser
import webbrowser
from dateutil.tz import tzutc
import hashlib

ROLECLINAMES = {
    "Administrator-EA" : "admin-ea",
    "Administrator" : "admin",
    "Power-User-EA" : "pu-ea",
    "Power-User" : "pu",
    "SecurityAudit" : "security",
    "Read-only-EA" : "read-ea",
    "Read-only" : "read"
}

AWS_DEFAULT_SSO_START_URL = "https://d-123456789.awsapps.com/start"
AWS_DEFAULT_SSO_REGION = "us-east-1"
AWS_DEFAULT_SSO_ACCOUNT_ID = "123456789"
AWS_DEFAULT_SSO_ROLE_NAME = "SSO-default"
AWS_DEFAULT_REGION = "us-east-1"
AWS_DEFAULT_OUTPUT = "json"
 
def get_aws_account_tag_list(accountId, credentials):
    orgs = boto3.client(
        'organizations',
        aws_access_key_id=credentials['accessKeyId'],
        aws_secret_access_key=credentials['secretAccessKey'],
        aws_session_token=credentials['sessionToken']
    )
    loopInit = True
    tags = []
    nextToken = ""
    while nextToken or loopInit:
        if loopInit:
            loopInit = False
            tagList = orgs.list_tags_for_resource(
                ResourceId = accountId
            )
        else:
            tagList = orgs.list_tags_for_resource(
                ResourceId = accountId,
                NextToken = nextToken
            )
        if "NextToken" in tagList:   
            nextToken = tagList['NextToken']
        tags.extend(tagList['Tags'])
    return tags

def get_aws_credentials(accountId, roleName):
    sso = boto3.client(
        'sso',
        region_name=AWS_DEFAULT_REGION)
    credentials = sso.get_role_credentials(
        accessToken=accessToken,
        roleName=roleName,
        accountId=accountId
    )
    return credentials['roleCredentials']

sso_oidc = boto3.client(
    'sso-oidc', 
    region_name=AWS_DEFAULT_SSO_REGION
)
clientName = 'AWS-SSO'
registration = sso_oidc.register_client(
    clientName = clientName,
    clientType = 'public'
)

clientExpiration = datetime.datetime.fromtimestamp(registration['clientSecretExpiresAt'], tzutc()).strftime('%Y-%m-%dT%H:%M:%SZ')

client_id = registration.get('clientId')
client_secret = registration.get('clientSecret')
auth = sso_oidc.start_device_authorization(
    clientId=client_id,
    clientSecret=client_secret,
    startUrl=AWS_DEFAULT_SSO_START_URL
)
url = auth.get('verificationUriComplete')
deviceCode = auth.get('deviceCode')
pollDelay =  auth.get('interval')

print("Complete AWS SSO login here: " + url)
webbrowser.open(url, new=2)

user_authenticated = False
while not user_authenticated:
    time.sleep(pollDelay)
    try:
        token_response = sso_oidc.create_token(
            clientId=client_id,
            clientSecret=client_secret,
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode=deviceCode,
            code=deviceCode
        )
        user_authenticated = True
    except sso_oidc.exceptions.AuthorizationPendingException:
        pass
    except sso_oidc.exceptions.SlowDownException:
        pollDelay += 5  # The device flow RFC defines the slow down delay to be an additional 5 seconds: https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
    except sso_oidc.exceptions.ExpiredTokenException:
        print('Error!  There was no response, please try again later')
        quit()

accessToken = token_response['accessToken']
accessTokenExpiration = (datetime.datetime.now(tzutc()) + datetime.timedelta(seconds=token_response['expiresIn'])).strftime('%Y-%m-%dT%H:%M:%SZ')

default_account_creds = get_aws_credentials(AWS_DEFAULT_SSO_ACCOUNT_ID, AWS_DEFAULT_SSO_ROLE_NAME)

aws_sso_cache_folder = os.path.join(str(Path.home()),".aws","sso","cache")
while not os.path.exists(aws_sso_cache_folder):
    os.makedirs(aws_sso_cache_folder)

aws_sso_cache_File = os.path.join(aws_sso_cache_folder, hashlib.sha1(AWS_DEFAULT_SSO_START_URL.encode('utf-8')).hexdigest() + ".json")
aws_sso_client_File = os.path.join(aws_sso_cache_folder, "botocore-client-id-" + AWS_DEFAULT_SSO_REGION + ".json")

with open (aws_sso_cache_File,'w') as cache_file:
    cache_file.write(json.dumps({
        'accessToken': accessToken,
        'expiresAt': accessTokenExpiration,
        'region': AWS_DEFAULT_SSO_REGION,
        'startUrl': AWS_DEFAULT_SSO_START_URL
    })) 
with open (aws_sso_client_File,'w') as client_file:
    client_file.write(json.dumps({
        'clientId': client_id,
        'clientSecret': client_secret,
        'expiresAt': clientExpiration
    })) 
os.chmod(aws_sso_cache_File, 0o600)
os.chmod(aws_sso_client_File, 0o600)

print("Discovering accounts in AWS SSO ...")
sso = boto3.client(
    'sso',
    region_name=AWS_DEFAULT_SSO_REGION
)

accounts = sso.list_accounts(
    maxResults=999,
    accessToken=accessToken
)

print("Discovering roles in AWS SSO & creating new configurations ...")
aws_folder = os.path.join(str(Path.home()),".aws")
while not os.path.exists(aws_folder):
    os.makedirs(aws_folder)

aws_config_file = os.path.join(aws_folder, 'config')
aws_credentials_file = os.path.join(aws_folder, 'credentials')
config = configparser.ConfigParser()
config.optionxform = str
config.read(aws_config_file)
credentials = configparser.ConfigParser()
credentials.optionxform = str
credentials.read(aws_credentials_file)

for account in accounts["accountList"]:
    roles = sso.list_account_roles(
        maxResults = 999,
        accessToken = accessToken,
        accountId = account["accountId"]
    )
    accountTags = get_aws_account_tag_list(account["accountId"], default_account_creds)
    temp_account_name = next((tag["Value"] for tag in accountTags if tag["Key"] == "cliName"), account["accountName"])
    temp_account_name = temp_account_name.replace(" ","").casefold()
    for role in roles["roleList"]:
        temp_role_name = role["roleName"]
        temp_role_accountId = role["accountId"]
        profileName = temp_account_name + "-" + ROLECLINAMES.get(temp_role_name, temp_role_name)
        section_name = "profile " + profileName
        temp_role_creds = get_aws_credentials(temp_role_accountId, temp_role_name)
        print("Generating a profile for " + profileName + ".")
        config.remove_section(section_name)
        config.add_section(section_name)
        credentials.remove_section(profileName)
        credentials.add_section(profileName)
        config.set(section_name, 'sso_start_url', AWS_DEFAULT_SSO_START_URL)
        config.set(section_name, 'sso_region', AWS_DEFAULT_SSO_REGION)
        config.set(section_name, 'sso_account_id', temp_role_accountId)
        config.set(section_name, 'sso_role_name', temp_role_name)
        config.set(section_name, 'region', AWS_DEFAULT_REGION)
        config.set(section_name, 'output', AWS_DEFAULT_OUTPUT)
        credentials.set(profileName, 'aws_access_key_id', temp_role_creds.get('accessKeyId'))
        credentials.set(profileName, 'aws_secret_access_key', temp_role_creds.get('secretAccessKey'))
        credentials.set(profileName, 'aws_session_token', temp_role_creds.get('sessionToken'))

with open(aws_config_file, 'w') as configfile:
    config.write(configfile)
with open(aws_credentials_file, 'w') as configfile:
    credentials.write(configfile)

os.chmod(aws_config_file, 0o644)
os.chmod(aws_credentials_file, 0o600)
print("Done.\n\nThe AWS CLI ready to use with the --profile option.")
