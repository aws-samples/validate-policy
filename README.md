## Validate IAM policy and/or role and notify in case of findings

This project creates Lambda function that automatically validates policy document defined when a policy or role is created or updated.  
Use cases include be notified when a policy contains error or security warnings. For example, when it is created via infrastructure as code (IaC).  
The resources are created or updated in the region where the CloudFormation stack is created.

## Overview

The CloudFormation template `cloudformation/template.yml` creates a stack with the following resources:

1. AWS Lambda function. The function's code is in `lambda/validate_policy.py` and is written in Python compatible with version 3.10.
1. Lambda function's execution role.
1. SNS topic.
1. SNS subscription for e-mail.

```
                          +-----------------+
                          | Lambda          |
                          | Execution Role  |
                          +--------+--------+
                                   |
                                   |                 +---------------------+
+--------------------+    +--------+--------+        |                     |
|EventBridge         +--->+ Lambda function +------->+Access Analyzer      |
|Rule                |    +--------+--------+        |                     |
+--------------------+             |                 +---------------------+
                                   |
                                   v
                          +--------+--------+
                          | CloudWatch Logs |
                          +-----------------+
```


## Supported events

It supports validate policy document when the following events occurs:
* CreatePolicy
* CreatePolicyVersion
* CreateRole
* UpdateAssumeRolePolicy
* PutRolePolicy
* PutUserPolicy
* PutGroupPolicy

> **NOTE**  
> If you miss some events that should be supported, feel free to open an issue or contribute with a pull request.


> **NOTE ABOUT REGIONS DEPLOY**  
> There is no reason to deploy this solution in any other region than North Virginia (`us-east-1`).  
> It uses CloudTrail events from IAM, which only happens in North Virginia, as IAM is a global service.


## Setup

These are the overall steps to deploy:

**Setup using CloudFormation**
1. Validate CloudFormation template file.
1. Create the CloudFormation stack.
1. Package the Lambda code into a `.zip` file.
1. Update Lambda function with the packaged code.

**After setup**
1. Trigger a test Lambda invocation.
1. Example of notification
1. Clean-up


## Setup using CloudFormation
To simplify setup and deployment, assign the values to the following variables. Replace the values according to your deployment options.

```bash
export AWS_REGION="us-east-1"
export CFN_STACK_NAME="validate-policy"
```

> **IMPORTANT:** Please, use AWS CLI v2

### 1. Validate CloudFormation template

Ensure the CloudFormation template is valid before use it.

```bash
aws cloudformation validate-template --template-body file://cloudformation/template.yml
```

### 2. Create CloudFormation stack

At this point it will create Lambda function with a dummy code.  
You will update it later.

Change the command to add the e-mail you want to receive notification. You MUST have access to this e-mail, as you will need to confirm subscription.

```bash
aws cloudformation create-stack --stack-name "${CFN_STACK_NAME}" \
  --capabilities CAPABILITY_IAM \
  --parameters  'ParameterKey=NotificationEmail,ParameterValue=<E-MAIL>@example.com' \
  --template-body file://cloudformation/template.yml && {
    ### Wait for stack to be created
    aws cloudformation wait stack-create-complete --stack-name "${CFN_STACK_NAME}"
}
```

If the stack creation fails, troubleshoot by reviewing the stack events. The typical failure reasons are insufficient IAM permissions.

if you see the error below, you need to change the e-mail parameter before run the commands above!

```
An error occurred (ValidationError) when calling the CreateStack operation: Parameter 'NotificationEmail' must match pattern ^[\w-\+]+(\.[\w]+)*@[\w-]+(\.[\w]+)*(\.[a-z]{2,})$
```


### 3. Create the packaged code

```bash
zip --junk-paths lambda.zip lambda/validate_policy.py
```

### 4. Update lambda package code

```bash
FUNCTION_NAME=$(aws cloudformation describe-stack-resources --stack-name "${CFN_STACK_NAME}" --query "StackResources[?LogicalResourceId=='LambdaFunction'].PhysicalResourceId" --output text)
aws lambda update-function-code --function-name "${FUNCTION_NAME}" --zip-file fileb://lambda.zip --publish
```


## After setup

### 1a. Trigger a test Lambda invocation with the AWS CLI

After the stack is created, AWS resources are not created or updated until a new SNS message is received. To test the function and create or update AWS resources with the current IP ranges for the first time, do a test invocation with the AWS CLI command below:

```bash
aws lambda invoke \
  --function-name "${FUNCTION_NAME}" \
  --cli-binary-format 'raw-in-base64-out' \
  --payload file://lambda/create-policy-version.json lambda_return.json
```

After successful invocation, you should receive the response below with no errors.

```json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

The content of the `lambda_return.json` will show if the policy has any finding.

You can use the files below from lambda folder to test.
* `create-policy-version.json` - This one generates finding
* `create-policy.json` - This one does not generate finding
* `create-role.json` - This one generates finding
* `put-group-policy.json` - This one generates finding
* `put-role-policy.json` - This one does not generate finding
* `put-user-policy.json` - This one does not generate finding
* `update-assume-role-policy.json` - This one does not generate finding

### 1b. Trigger a test Lambda invocation with the AWS Console

Alternatively, you can invoke the test event in the AWS Lambda console with sample event from file `lambda/create-policy-version.json`.


### 2. Example of notification

```
An IAM Policy was updated with findings

IAM ARN: arn:aws:iam::123412341234:policy/test-validate-policy 
Policy Version: v5 
Event: CreatePolicyVersion
Region: us-east-1
Actor: arn:aws:sts::123412341234:assumed-role/me/leo
Source IP Address: 11.22.33.44
User Agent: AWS Internal
Findings: 
  SECURITY_WARNING: Using wildcards (*) in the action and the resource can be overly permissive because it allows iam:PassRole permissions on all resources. We recommend that you specify resource ARNs or add the iam:PassedToService condition key to your statement.
  WARNING: Using wildcards (*) in the action and the resource can allow creation of unintended service-linked roles because it allows iam:CreateServiceLinkedRole permissions on all resources. We recommend that you specify resource ARNs instead.


This notification was generated by the Lambda function arn:aws:lambda:us-east-1:123412341234:function:validate-policy-LambdaFunction-l9GDa18O05hO
```

### 3. Clean-up

Remove the temporary files and remove CloudFormation stack.

```bash
rm lambda.zip
rm lambda_return.json
aws cloudformation delete-stack --stack-name "${CFN_STACK_NAME}"
unset AWS_REGION
unset CFN_STACK_NAME
```


## Lambda function customization

After the stack is created, you can customize the Lambda function's execution log level by editing the function's [environment variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html).

* `LOG_LEVEL`: **Optional**. Set log level to increase or reduce verbosity. The default value is `INFO`. Possible values are:
  * CRITICAL
  * ERROR
  * WARNING
  * INFO
  * DEBUG

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
