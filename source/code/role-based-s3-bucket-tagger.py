"""AWS Lambda resource tagger for Amazon S3 buckets.

   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0

   This AWS Lambda extracts tags from the Tag Tamer "tag_tamer_roles"
   DynamoDB table.  This table is created during Tag Tamer solution
   installation.

   These extracted tags are applied to new Amazon S3 buckets.
"""

import json

import boto3
import botocore


def get_role_tags(role_arn):
    """Get resource tags assigned to a specified IAM role in DynamoDB.

    Tag Tamer deploys a DynamoDB table named "tag_tamer_roles"
    This table maps IAM roles to resource tag key:value pairs.

    Args:
        role_arn: IAM role arn of the entity creating the S3 bucket.

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


def set_s3_bucket_resource_tags(s3_bucket_name, resource_tags):
    """Applies a list of passed resource tags to the Amazon S3 buckets.

    Args:
        s3_bucket_name: S3 bucket name to tag
        resource_tags: a list of key:string,value:string resource tag dictionaries

    Returns:
        Returns True if tag application successful and False if not

    Raises:
        AWS Python API "Boto3" returned client errors
    """

    client = boto3.client("s3")
    try:
        response = client.get_bucket_location(Bucket=s3_bucket_name)
    except botocore.exceptions.ClientError as error:
        print("Boto3 API returned error: ", error)
        print("No Tags Applied To: ", s3_bucket_name)
        return False

    if "LocationConstraint" in response.keys():
        try:
            response = client.put_bucket_tagging(
                Bucket=s3_bucket_name, Tagging={"TagSet": resource_tags}
            )
            return True
        except botocore.exceptions.ClientError as error:
            print("Boto3 API returned error: ", error)
            print("No Tags Applied To: ", s3_bucket_name)
            return False
    else:
        return False


def cloudtrail_event_parser(event):
    """Extract list of new S3 bucket attributes.

    These attributes are extracted from the
    AWS CloudTrail resource creation event.

    Args:
        event: a CloudTrail event

    Returns:
        s3_bucket_name: name of the created S3 bucket
        resource_date: date+time the S3 bucket was created
        role_arn: IAM role ARN of entity creating the S3 bucket

    Raises:
        none
    """

    s3_bucket_name = event.get("detail").get("requestParameters").get("bucketName", "")

    resource_date = event.get("detail").get("eventTime", "")

    # Verify assumed IAM role ARN assumed to create the new S3 bucket
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

    return s3_bucket_name, resource_date, role_arn


def lambda_handler(event, context):
    s3_bucket_name, resource_date, role_arn = cloudtrail_event_parser(event)

    # Tag S3 bucket created by matched assumed IAM role
    iam_role_resource_tags = get_role_tags(role_arn)
    if iam_role_resource_tags:
        resource_tags = []
        resource_tags.append({"Key": "IAM Role assumed", "Value": role_arn})
        resource_tags += iam_role_resource_tags
        if resource_date:
            resource_tags.append({"Key": "Date created", "Value": resource_date})
        if s3_bucket_name:
            if set_s3_bucket_resource_tags(s3_bucket_name, resource_tags):
                print(
                    "'statusCode': 200,\n"
                    f"'S3 Bucket Name': {s3_bucket_name}\n"
                    f"'body': {json.dumps(resource_tags)}"
                )
            else:
                print(
                    "'statusCode': 500,\n"
                    f"'No tags applied to Resource ID': {s3_bucket_name},\n"
                    f"'Lambda function name': {context.function_name},\n"
                    f"'Lambda function version': {context.function_version}"
                )
        else:
            print(
                "'statusCode': 200,\n"
                f"'No Amazon S3 resources to tag': 'Event ID: {event.get('id')}'"
            )
    else:
        print(
            "'statusCode': 200,\n"
            f"'No matching IAM role with tags found': 'Event ID: {event.get('id')}'"
        )
