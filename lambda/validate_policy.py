"""
Validate IAM policy using Access Analyzer when customer creates policy and/or changes role.
It is trigged by EventBridge rule.
"""


# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0


import json
import logging
import os
from collections.abc import Callable
from typing import Any, NamedTuple

import boto3  # type: ignore

# Security warnings: report when the policy allows access that we consider overly permissive.
# Errors:            report when a part of the policy is not functional.
# Warnings:          report non-security issues when a policy does not conform to policy writing best practices.
# Suggestions:       recommend stylistic improvements in the policy that do not impact access.

# It will consider all finding types below to generate the notification.
# If you want to be notified only for certain finding types, change the variable
# below according to your requirement.
CONST_FINDING_TYPE = {'ERROR', 'SECURITY_WARNING', 'SUGGESTION', 'WARNING'}

CONST_DETAIL = 'detail'
CONST_ERROR_CODE = 'errorCode'
CONST_EVENT_NAME = 'eventName'
CONST_FINDINGS = 'findings'
CONST_NEXT_TOKEN = 'nextToken' # nosec B105

####### Get values from environment variables  ######

## Logging level options in less verbosity order. INFO is the default.
## If you enable DEBUG, it will log boto3 calls as well.
# CRITICAL
# ERROR
# WARNING
# INFO
# DEBUG

#########

# Get logging level from environment variable
if (LOG_LEVEL := os.getenv('LOG_LEVEL', '').upper()) not in {'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'}:
    LOG_LEVEL = 'INFO'

# Set up logging. Set the level if the handler is already configured.
if len(logging.getLogger().handlers) > 0:
    logging.getLogger().setLevel(LOG_LEVEL)
else:
    logging.basicConfig(level=LOG_LEVEL)


SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN', '')
if not (SNS_TOPIC_ARN := os.getenv('SNS_TOPIC_ARN', '')):
    logging.error('SNS_TOPIC_ARN environment variable not set, it will validate policy but will NOT send notification!')

# Define client for services
aa_client = boto3.client('accessanalyzer')
sns_client = boto3.client('sns')

def validate_policy(client: Any, policy_document: str, policy_type: str, resource_type: str) -> list[Any]:
    """Validate the policy document using access analyzer"""

    logging.info('validate_policy start')
    logging.debug('Parameter client: %s', client)
    logging.debug('Parameter policy_document: %s', policy_document)

    locale: str = 'EN'
    findings: list[Any] = []

    # Check if the policy is valid
    kwargs = {
        'policyDocument': policy_document,
        'locale': locale,
        'policyType': policy_type
    }
    if resource_type:
        kwargs['validatePolicyResourceType'] = resource_type

    logging.info('Check if the policy document is valid')
    response = client.validate_policy(**kwargs)
    logging.info('Checked if the policy document is valid')
    logging.debug('Response: %s', response)

    while True:
        if CONST_FINDINGS in response:
            for finding in response[CONST_FINDINGS]:
                if finding['findingType'] in CONST_FINDING_TYPE:
                    findings.append(finding)

        if CONST_NEXT_TOKEN in response:
            kwargs = {
                'policyDocument': policy_document,
                'locale': locale,
                'policyType': policy_type,
                'nextToken': response[CONST_NEXT_TOKEN]
            }
            if resource_type:
                kwargs['validatePolicyResourceType'] = resource_type

            logging.info('Found nextToken, validate policy again, get next findings')
            response = client.validate_policy(**kwargs)
            logging.info('Found nextToken, validate policy again, got next findings')
            logging.debug('Response: %s', response)
        else:
            break

    #print(findings)
    findings.sort(key=lambda x: x['findingType'])

    logging.debug('Function return: %s', findings)
    logging.info('validate_policy end')
    return findings

### Message functions
def message_create_policy(event: Any, context: Any, findings: list[Any]) -> tuple[str, str]:
    """Format violation message and subject"""

    subject: str = 'Violation - IAM Policy is out of compliance'

    message: str = ''
    message = 'An IAM Policy was created with findings\n\n'
    message += 'IAM ARN: ' + event['responseElements']['policy']['arn'] + ' \n'
    message += message_violation(event, context, findings)

    return subject, message

def message_create_policy_version(event: Any, context: Any, findings: list[Any]) -> tuple[str, str]:
    """Format violation message and subject"""

    subject: str = 'Violation - IAM Policy is out of compliance'

    message: str = ''
    message = 'An IAM Policy was updated with findings\n\n'
    message += 'IAM ARN: ' + event['requestParameters']['policyArn'] + ' \n'
    message += 'Policy Version: ' + event['responseElements']['policyVersion']['versionId'] + ' \n'
    message += message_violation(event, context, findings)

    return subject, message

def message_create_role(event: Any, context: Any, findings: list[Any]) -> tuple[str, str]:
    """Format violation message and subject"""

    subject: str = 'Violation - IAM Role Trust policy is out of compliance'

    message: str = ''
    message = 'An IAM Role Trust policy was created with findings\n\n'
    message += 'IAM ARN: ' + event['responseElements']['role']['arn'] + ' \n'
    message += message_violation(event, context, findings)

    return subject, message

def message_update_assume_role_policy(event: Any, context: Any, findings: list[Any]) -> tuple[str, str]:
    """Format violation message and subject"""

    subject: str = 'Violation - IAM Role Trust policy is out of compliance'

    message: str = ''
    message = 'An IAM Role Trust policy was updated with findings\n\n'
    message += 'Role Name: ' + event['requestParameters']['roleName'] + ' \n'
    message += message_violation(event, context, findings)

    return subject, message

def message_put_role_policy(event: Any, context: Any, findings: list[Any]) -> tuple[str, str]:
    """Format violation message and subject"""

    subject: str = 'Violation - IAM Role in-line policy is out of compliance'

    message: str = ''
    message = 'An IAM Role in-line policy was created/updated with findings\n\n'
    message += 'Role Name: ' + event['requestParameters']['roleName'] + ' \n'
    message += 'Policy Name: ' + event['requestParameters']['policyName'] + ' \n'
    message += message_violation(event, context, findings)

    return subject, message

def message_put_user_policy(event: Any, context: Any, findings: list[Any]) -> tuple[str, str]:
    """Format violation message and subject"""

    subject: str = 'Violation - IAM User in-line policy is out of compliance'

    message: str = ''
    message = 'An IAM User in-line policy was created/updated with findings\n\n'
    message += 'User Name: ' + event['requestParameters']['userName'] + ' \n'
    message += 'Policy Name: ' + event['requestParameters']['policyName'] + ' \n'
    message += message_violation(event, context, findings)

    return subject, message

def message_put_group_policy(event: Any, context: Any, findings: list[Any]) -> tuple[str, str]:
    """Format violation message and subject"""

    subject: str = 'Violation - IAM Group in-line policy is out of compliance'

    message: str = ''
    message = 'An IAM Group in-line policy was created/updated with findings\n\n'
    message += 'Group Name: ' + event['requestParameters']['groupName'] + ' \n'
    message += 'Policy Name: ' + event['requestParameters']['policyName'] + ' \n'
    message += message_violation(event, context, findings)

    return subject, message

def message_violation(event: Any, context: Any, findings: list[Any]) -> str:
    """Add common details to violation message"""

    message: str = ''
    message += 'Event: ' + event['eventName'] + '\n'
    message += 'Region: ' + event['awsRegion'] + '\n'
    message += 'Actor: ' + event['userIdentity']['arn'] + '\n'
    message += 'Source IP Address: ' + event['sourceIPAddress'] + '\n'
    message += 'User Agent: ' + event['userAgent'] + '\n'

    message += 'Findings: \n'
    for finding in findings:
        message += '  ' + finding['findingType'] + ': ' + finding['findingDetails'] + '\n'

    message += "\n\n"
    message += "This notification was generated by the Lambda function " + context.invoked_function_arn

    return message


### Validate functions
def validate_create_policy(event_detail: Any) -> list[Any]:
    """Validate policy from CreatePolicy API call"""
    findings = validate_event(event_detail['requestParameters'], 'policyDocument', 'IDENTITY_POLICY', '', 'Policy is not valid', ['policyName'])
    return findings

def validate_create_policy_version(event_detail: Any) -> list[Any]:
    """Validate policy from CreatePolicyVersion API call"""
    findings = validate_event(event_detail['requestParameters'], 'policyDocument', 'IDENTITY_POLICY', '', 'Policy is not valid', ['policyArn'])
    return findings

def validate_create_role(event_detail: Any) -> list[Any]:
    """Validate policy from CreateRole API call"""
    findings = validate_event(event_detail['requestParameters'], 'assumeRolePolicyDocument', 'RESOURCE_POLICY', 'AWS::IAM::AssumeRolePolicyDocument', 'Role trust policy is not valid', ['roleName'])
    return findings

def validate_update_assume_role_policy(event_detail: Any) -> list[Any]:
    """Validate policy from UpdateAssumeRolePolicy API call"""
    findings = validate_event(event_detail['requestParameters'], 'policyDocument', 'RESOURCE_POLICY', 'AWS::IAM::AssumeRolePolicyDocument', 'Role trust policy is not valid', ['roleName'])
    return findings

def validate_put_role_policy(event_detail: Any) -> list[Any]:
    """Validate policy from PutRolePolicy API call"""
    findings = validate_event(event_detail['requestParameters'], 'policyDocument', 'IDENTITY_POLICY', '', 'Role in-line policy is not valid', ['roleName', 'policyName'])
    return findings

def validate_put_user_policy(event_detail: Any) -> list[Any]:
    """Validate policy from PutUserPolicy API call"""
    findings = validate_event(event_detail['requestParameters'], 'policyDocument', 'IDENTITY_POLICY', '', 'User in-line policy is not valid', ['userName', 'policyName'])
    return findings

def validate_put_group_policy(event_detail: Any) -> list[Any]:
    """Validate policy from PutGroupPolicy API call"""
    findings = validate_event(event_detail['requestParameters'], 'policyDocument', 'IDENTITY_POLICY', '', 'Group in-line policy is not valid', ['groupName', 'policyName'])
    return findings

def validate_event(request_parameters: dict[str, Any], key_name: str, policy_type: str, resource_type: str, log_message: str, log_keys: list[str]) -> list[Any]:
    """Validate policy based on event details"""
    policy_document = json.loads(request_parameters[key_name])
    findings = validate_policy(aa_client, json.dumps(policy_document), policy_type, resource_type)
    if len(findings) > 0:
        logging.info(log_message)
        for key in log_keys:
            logging.info('  %s: %s', key, request_parameters[key])
    return findings

class IAMEvent(NamedTuple):
    """NamedTuple to hold IAM event functions"""
    validate_function: Callable
    message_function: Callable

ALL_EVENTS: dict[str, IAMEvent] = {
    'CreatePolicy': IAMEvent(validate_create_policy, message_create_policy),
    'CreatePolicyVersion': IAMEvent(validate_create_policy_version, message_create_policy_version),
    'CreateRole': IAMEvent(validate_create_role, message_create_role),
    'UpdateAssumeRolePolicy': IAMEvent(validate_update_assume_role_policy, message_update_assume_role_policy),
    'PutRolePolicy': IAMEvent(validate_put_role_policy, message_put_role_policy),
    'PutUserPolicy': IAMEvent(validate_put_user_policy, message_put_user_policy),
    'PutGroupPolicy': IAMEvent(validate_put_group_policy, message_put_group_policy)
}

#======================================================================================================================
# Lambda entry point
#======================================================================================================================

def lambda_handler(event, context):
    """Lambda function handler"""
    logging.info('lambda_handler start')
    logging.debug('Parameter event: %s', json.dumps(event))
    logging.debug('Parameter context: %s', context)

    return_value: dict[str, str] = {}
    findings: list[Any] = []
    try:
        if CONST_DETAIL not in event:
            logging.warning('Detail not found. It is expecting an event from CloudTrail. Nothing to do.')
            return False

        event_detail: dict[str, Any] = event['detail']
        if CONST_ERROR_CODE in event_detail:
            error_code: str = event_detail['errorCode']
            error_message: str = event_detail['errorMessage']
            logging.info('Error %s found. Nothing to do.', error_code)
            logging.info('Error message: %s', error_message)
            return False

        if CONST_EVENT_NAME not in event_detail:
            logging.warning('Event name not found. It is expecting an event from CloudTrail. Nothing to do.')
            return False

        event_name: str = event_detail['eventName']
        logging.info('Event: %s', event_name)

        if event_name not in ALL_EVENTS:
            logging.warning('Event not supported. It is expecting one of %s', ALL_EVENTS.keys())
            return False

        # Call the function
        findings = ALL_EVENTS[event_name].validate_function(event_detail)

        if len(findings) > 0:
            logging.debug('Findings: %s', findings)

            subject, message = ALL_EVENTS[event_name].message_function(event_detail, context, findings)
            logging.info('Subject: %s', subject)
            logging.info('Message: \n%s', message)
            return_value = {'subject': subject, 'message': message}

            if SNS_TOPIC_ARN:
                logging.info('Sending notification to SNS topic: %s', SNS_TOPIC_ARN)
                response = sns_client.publish(TopicArn=SNS_TOPIC_ARN, Message=message, Subject=subject)
                logging.info('Sent notification to SNS topic: %s', SNS_TOPIC_ARN)
                logging.debug('Response: %s', response)

    except Exception as error:
        logging.exception(error)
        raise error

    logging.info('Function return: %s', return_value)
    logging.info('lambda_handler end')
    return return_value

# Used to run and validate lambda locally
class LambdaContext(NamedTuple):
    """Lambda context to mimic AWS Lambda context"""
    aws_request_id: str
    log_group_name: str
    log_stream_name: str
    function_name: str
    memory_limit_in_mb: int
    function_version: str
    invoked_function_arn: str
    client_context: Any
    identity: Any

if __name__ == '__main__':
    context_test = LambdaContext(
        aws_request_id='1b4daa92-1234-1234-1234-ae023531102b',
        log_group_name='/aws/lambda/log-event',
        log_stream_name='2023/07/11/[$LATEST]9ddf03096836450db2ddd916c79677a2',
        function_name='log-event',
        memory_limit_in_mb=128,
        function_version='$LATEST',
        invoked_function_arn='arn:aws:lambda:us-east-1:123412341234:function:log-event',
        client_context=None,
        identity=None
    )
    with open('create-policy-version.json', 'r', encoding='utf-8') as event_file:
        event_test: dict[str, Any] = json.loads(event_file.read())
        lambda_handler(event_test, context_test)
