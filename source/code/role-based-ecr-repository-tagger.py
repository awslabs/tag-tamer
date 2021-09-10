"""AWS Lambda resource tagger for Amazon ECR repositories.

   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0

   This AWS Lambda extracts tags from the Tag Tamer "tag_tamer_roles"
   DynamoDB table.  This table is created during Tag Tamer solution
   installation.

   These extracted tags are applied to new Amazon ECR repositories
"""

import json

import boto3
import botocore


def get_role_tags(role_arn):
    """Get resource tags assigned to a specified IAM role in DynamoDB.

    Tag Tamer deploys a DynamoDB table named "tag_tamer_roles"
    This table maps IAM roles to resource tag key:value pairs.

    Args:
        role_arn: IAM role arn of the entity creating the ECR repository.

    Returns:
        Returns a list of key:string,value:string resource tag dictionaries
        assigned to the role or an empty list if no tags assigned to the role.

    Raises:
        AWS Python API "Boto3" returned client errors
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table("tag_tamer_roles")
    try:
        response = table.get_item(
            Key={"role_arn": role_arn}, ProjectionExpression="tags"
        )
        return response["Item"]["tags"]
    except botocore.exceptions.ClientError as error:
        print("Boto3 API returned error: ", error)
        return []


# Apply resource tags to new ECR repositories
def set_ecr_repository_tags(ecr_repository_arn, resource_tags):
    """Applies a list of passed resource tags to the AWS ECR repository.

    Args:
        ecr_repository_arn: ECR repository identifier/ARN
        resource_tags: a list of key:string,value:string resource tag dictionaries

    Returns:
        Returns True if tag application successful and False if not

    Raises:
        AWS Python API "Boto3" returned client errors
    """

    client = boto3.client("ecr")
    try:
        response = client.tag_resource(
            resourceArn=ecr_repository_arn, tags=resource_tags
        )
    except botocore.exceptions.ClientError as error:
        print("Boto3 API returned error: ", error)
        print("No Tags Applied To: ", ecr_repository_arn)
        return False
    return True


def cloudtrail_event_parser(event):
    """Extract list of new ECR repository attributes.

    These attributes are extracted from the
    AWS CloudTrail resource creation event.

    Args:
        event: a CloudTrail event passed to this Lambda by an EventBridge rule trigger

    Returns:
        ecr_repository_arn: the ARN of the new ECR repository
        resource_date: date the ECR repositories were created
        role_arn: IAM role ARN of entity creating the ECR repositories

    Raises:
        none
    """

    ecr_repository_arn = (
        event.get("detail")
        .get("responseElements")
        .get("repository")
        .get("repositoryArn", "")
    )

    resource_date = event.get("detail").get("eventTime", "")

    # Verify assumed IAM role ARN assumed to create the new ECR repository
    if event.get("detail").get("userIdentity").get("type") == "AssumedRole":
        role_arn = (
            event.get("detail")
            .get("userIdentity")
            .get("sessionContext")
            .get("sessionIssuer")
            .get("arn", "")
        )
    else:
        role_arn = ""

    return ecr_repository_arn, resource_date, role_arn


def lambda_handler(event, context):
    ecr_repository_arn, resource_date, role_arn = cloudtrail_event_parser(event)

    # Tag ECR repository created by matched assumed IAM role
    iam_role_resource_tags = get_role_tags(role_arn)
    if iam_role_resource_tags:
        resource_tags = []
        resource_tags.append({"Key": "IAM Role assumed", "Value": role_arn})
        resource_tags += iam_role_resource_tags
        if resource_date:
            resource_tags.append({"Key": "Date created", "Value": resource_date})
        if ecr_repository_arn:
            if set_ecr_repository_tags(ecr_repository_arn, resource_tags):
                print(
                    "'statusCode': 200,\n"
                    f"'Resource ID': {ecr_repository_arn}\n"
                    f"'body': {json.dumps(resource_tags)}"
                )
            else:
                print(
                    "'statusCode': 500,\n"
                    f"'No tags applied to Resource ID': {ecr_repository_arn},\n"
                    f"'ECR repository name': {context.function_name},\n"
                    f"'ECR repository version': {context.function_version}"
                )
        else:
            print(
                "'statusCode': 200,\n"
                f"'No Amazon ECR repositories to tag': 'Event ID: {event.get('id')}'"
            )
    else:
        print(
            "'statusCode': 200,\n"
            f"'No matching IAM role with tags found': 'Event ID: {event.get('id')}'"
        )
