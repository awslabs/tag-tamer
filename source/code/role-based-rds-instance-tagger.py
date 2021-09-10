"""AWS Lambda resource tagger for Amazon RDS instances.

   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0

   This AWS Lambda extracts tags from the Tag Tamer "tag_tamer_roles"
   DynamoDB table.  This table is created during Tag Tamer solution
   installation.

   These extracted tags are applied to new Amazon RDS instances
"""

import json

import boto3
import botocore


def get_role_tags(role_arn):
    """Get resource tags assigned to a specified IAM role in DynamoDB.

    Tag Tamer deploys a DynamoDB table named "tag_tamer_roles"
    This table maps IAM roles to resource tag key:value pairs.

    Args:
        role_arn: IAM role arn of the entity creating the RDS instance.

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


# Apply resource tags to new RDS instances
def set_rds_instance_tags(rds_instance_id, resource_tags):
    """Applies a list of passed resource tags to the Amazon RDS instance.

    Args:
        rds_instance_id: RDS instance identifier/ARN
        resource_tags: a list of key:string,value:string
        resource tag dictionaries

    Returns:
        Returns True if tag application successful and False if not

    Raises:
        AWS Python API "Boto3" returned client errors
    """
    client = boto3.client("rds")
    try:
        response = client.add_tags_to_resource(
            ResourceName=rds_instance_id, Tags=resource_tags
        )
    except botocore.exceptions.ClientError as error:
        print("Boto3 API returned error: ", error)
        print("No Tags Applied To: ", rds_instance_id)
        return False
    return True


def cloudtrail_event_parser(event):
    """Extract list of new RDS instance attributes.

    These attributes are extracted from the
    AWS CloudTrail resource creation event.

    Args:
        event: a CloudTrail event passed to this Lambda by an EventBridge rule trigger

    Returns:
        rds_instance_id: the ARN of the new RDS instance
        resource_date: date the RDS instances were created
        role_arn: IAM role ARN of entity creating the RDS instances

    Raises:
        none
    """

    rds_instance_id = (
        event.get("detail").get("responseElements").get("dBInstanceArn", "")
    )

    resource_date = event.get("detail").get("eventTime", "")

    # Verify assumed IAM role ARN assumed to create the new RDS instance
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

    return rds_instance_id, resource_date, role_arn


def lambda_handler(event, context):
    rds_instance_id, resource_date, role_arn = cloudtrail_event_parser(event)

    # Tag RDS instance created by matched assumed IAM role
    iam_role_resource_tags = get_role_tags(role_arn)
    if iam_role_resource_tags:
        resource_tags = []
        resource_tags.append({"Key": "IAM Role assumed", "Value": role_arn})
        resource_tags += iam_role_resource_tags
        if resource_date:
            resource_tags.append({"Key": "Date created", "Value": resource_date})
        if rds_instance_id:
            if set_rds_instance_tags(rds_instance_id, resource_tags):
                print(
                    "'statusCode': 200,\n"
                    f"'Resource ID': {rds_instance_id}\n"
                    f"'body': {json.dumps(resource_tags)}"
                )
            else:
                print(
                    "'statusCode': 500,\n"
                    f"'No tags applied to Resource ID': {rds_instance_id},\n"
                    f"'Lambda function name': {context.function_name},\n"
                    f"'Lambda function version': {context.function_version}"
                )
        else:
            print(
                "'statusCode': 200,\n"
                f"'No Amazon RDS instances to tag': 'Event ID: {event.get('id')}'"
            )
    else:
        print(
            "'statusCode': 200,\n"
            f"'No matching IAM role with tags found': 'Event ID: {event.get('id')}'"
        )
