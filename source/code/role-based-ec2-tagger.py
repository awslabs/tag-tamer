"""AWS Lambda resource tagger for Amazon EC2 instances.

   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0

   This AWS Lambda extracts tags from the Tag Tamer "tag_tamer_roles"
   DynamoDB table.  This table is created during Tag Tamer solution
   installation.

   These extracted tags are applied to new Amazon EC2 instances & their
   attached EBS volumes.
"""

import json

import boto3
import botocore


def get_role_tags(role_arn):
    """Get resource tags assigned to a specified IAM role in DynamoDB.

    Tag Tamer deploys a DynamoDB table named "tag_tamer_roles"
    This table maps IAM roles to resource tag key:value pairs.

    Args:
        role_arn: IAM role arn of the entity creating the EC2 instance.

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


# Apply resource tags to new EC2 instances & attached EBS volumes
def set_ec2_resource_tags(ec2_instance_id, resource_tags):
    """Applies a list of passed resource tags to the Amazon EC2 instance.
       Also applies the same resource tags to EBS volumes attached to instance.

    Args:
        ec2_instance_id: EC2 instance identifier
        resource_tags: a list of key:string,value:string
        resource tag dictionaries

    Returns:
        Returns True if tag application successful and False if not

    Raises:
        AWS Python API "Boto3" returned client errors
    """
    client = boto3.client("ec2")
    try:
        response = client.create_tags(Resources=[ec2_instance_id], Tags=resource_tags)
        response = client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [ec2_instance_id]}]
        )
        try:
            for volume in response.get("Volumes"):
                ec2 = boto3.resource("ec2")
                ec2_vol = ec2.Volume(volume["VolumeId"])
                vol_tags = ec2_vol.create_tags(Tags=resource_tags)
        except botocore.exceptions.ClientError as error:
            print("Boto3 API returned error: ", error)
            print("No Tags Applied To: ", response["Volumes"])
            return False
    except botocore.exceptions.ClientError as error:
        print("Boto3 API returned error: ", error)
        print("No Tags Applied To: ", ec2_instance_id)
        return False
    return True


def cloudtrail_event_parser(event):
    """Extract list of new EC2 instance attributes.

    These attributes are extracted from the
    AWS CloudTrail resource creation event.

    Args:
        event: a CloudTrail event passed to this Lambda by an EventBridge rule trigger

    Returns:
        instances_set: list of EC2 instances & parameter dictionaries
        resource_date: date the EC2 instances were created
        role_arn: IAM role ARN of entity creating the EC2 instances

    Raises:
        none
    """
    # Extract & return the list of new EC2 instance(s) and their parameters
    instances_set = (
        event.get("detail").get("responseElements").get("instancesSet", "")
    )

    # Extract the date & time of the EC2 instance creation
    resource_date = event.get("detail").get("eventTime", "")

    # Verify assumed IAM role ARN assumed to create the new EC2 instance(s)
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

    return instances_set, resource_date, role_arn


def lambda_handler(event, context):
    instances_set, resource_date, role_arn = cloudtrail_event_parser(event)

    # Tag EC2 instances created by matched assumed IAM role
    iam_role_resource_tags = get_role_tags(role_arn)
    if iam_role_resource_tags:
        resource_tags = []
        resource_tags.append({"Key": "IAM Role assumed", "Value": role_arn})
        resource_tags += iam_role_resource_tags
        if resource_date:
            resource_tags.append({"Key": "Date created", "Value": resource_date})
        if instances_set:
            for item in instances_set.get("items"):
                ec2_instance_id = item.get("instanceId")
                if set_ec2_resource_tags(ec2_instance_id, resource_tags):
                    print(
                        "'statusCode': 200,\n"
                        f"'Resource ID': {ec2_instance_id}\n"
                        f"'body': {json.dumps(resource_tags)}"
                    )
                else:
                    print(
                        "'statusCode': 500,\n"
                        f"'No tags applied to Resource ID': {ec2_instance_id},\n"
                        f"'Lambda function name': {context.function_name},\n"
                        f"'Lambda function version': {context.function_version}"
                    )
        else:
            print(
                "'statusCode': 200,\n"
                f"'No Amazon EC2 resources to tag': 'Event ID: {event.get('id')}'"
            )
    else:
        print(
            "'statusCode': 200,\n"
            f"'No matching IAM role with tags found': 'Event ID: {event.get('id')}'"
        )
