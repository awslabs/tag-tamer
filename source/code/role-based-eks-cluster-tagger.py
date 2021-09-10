"""AWS Lambda resource tagger for Amazon EKS clusters.

   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
   SPDX-License-Identifier: MIT-0

   This AWS Lambda extracts tags from the Tag Tamer "tag_tamer_roles"
   DynamoDB table.  This table is created during Tag Tamer solution
   installation.

   These extracted tags are applied to new Amazon EKS clusters
"""

import json

import boto3
import botocore


def get_role_tags(role_arn):
    """Get resource tags assigned to a specified IAM role in DynamoDB.

    Tag Tamer deploys a DynamoDB table named "tag_tamer_roles"
    This table maps IAM roles to resource tag key:value pairs.

    Args:
        role_arn: IAM role arn of the entity creating the EKS cluster.

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


# Apply resource tags to new EKS clusters
def set_eks_cluster_tags(eks_cluster_arn, resource_tags):
    """Applies a list of passed resource tags to the AWS EKS cluster.

    Args:
        eks_cluster_arn: EKS cluster identifier/ARN
        resource_tags: a list of key:string,value:string resource tag dictionaries

    Returns:
        Returns True if tag application successful and False if not

    Raises:
        AWS Python API "Boto3" returned client errors
    """
    # for EKS Boto3 API convert list of tags dicts to single key:value tag dict
    tag_dict = {}
    for tag in resource_tags:
        tag_dict[tag["Key"]] = tag["Value"]

    client = boto3.client("eks")
    try:
        response = client.tag_resource(resourceArn=eks_cluster_arn, tags=tag_dict)
    except botocore.exceptions.ClientError as error:
        print("Boto3 API returned error: ", error)
        print("No Tags Applied To: ", eks_cluster_arn)
        return False
    return True


def cloudtrail_event_parser(event):
    """Extract list of new EKS cluster attributes.

    These attributes are extracted from the
    AWS CloudTrail resource creation event.

    Args:
        event: a CloudTrail event passed to this Lambda by an EventBridge rule trigger

    Returns:
        eks_cluster_arn: the ARN of the new EKS cluster
        resource_date: date the EKS clusters were created
        role_arn: IAM role ARN of entity creating the EKS clusters

    Raises:
        none
    """

    eks_cluster_arn = (
        event.get("detail").get("responseElements").get("cluster").get("arn", "")
    )

    resource_date = event.get("detail").get("eventTime", "")

    # Verify assumed IAM role ARN assumed to create the new EKS Cluster
    if event.get("detail").get("userIdentity").get("type") == "AssumedRole":
        role_arn = (
            event.get("detail")
            .get("userIdentity")
            .get("sessionContext")
            .get("sessionIssuer")
            .get("arn", "")
        )
    else:
        role_arn = None

    return eks_cluster_arn, resource_date, role_arn


def lambda_handler(event, context):
    eks_cluster_arn, resource_date, role_arn = cloudtrail_event_parser(event)

    # Tag EKS Cluster created by matched assumed IAM role
    iam_role_resource_tags = get_role_tags(role_arn)
    if iam_role_resource_tags:
        resource_tags = []
        resource_tags.append({"Key": "IAM Role assumed", "Value": role_arn})
        resource_tags += iam_role_resource_tags
        if resource_date:
            resource_tags.append({"Key": "Date created", "Value": resource_date})
        if eks_cluster_arn:
            if set_eks_cluster_tags(eks_cluster_arn, resource_tags):
                print(
                    "'statusCode': 200,\n"
                    f"'Resource ID': {eks_cluster_arn}\n"
                    f"'body': {json.dumps(resource_tags)}"
                )
            else:
                print(
                    "'statusCode': 500,\n"
                    f"'No tags applied to Resource ID': {eks_cluster_arn},\n"
                    f"'EKS cluster name': {context.function_name},\n"
                    f"'EKS cluster version': {context.function_version}"
                )
        else:
            print(
                "'statusCode': 200,\n"
                f"'No Amazon EKS clusters to tag': 'Event ID: {event.get('id')}'"
            )
    else:
        print(
            "'statusCode': 200,\n"
            f"'No matching IAM role with tags found': 'Event ID: {event.get('id')}'"
        )
