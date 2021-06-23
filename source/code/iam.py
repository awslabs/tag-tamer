#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Getter & setter for AWS IAM

# Import administrative functions
from admin import execution_status

# Import AWS modules for python
import botocore
from botocore import exceptions
import boto3
from boto3.dynamodb.conditions import Key, Attr

# Import logging module
import logging

# Import sys to return name of current function
import sys

log = logging.getLogger(__name__)

# Define AWS Config class to get/set IAM Roles using Boto3
class roles:

    # Class constructor
    def __init__(self, region, **session_credentials):
        self.my_status = execution_status()
        self.region = region
        self.session_credentials = dict()
        self.session_credentials["AccessKeyId"] = session_credentials["AccessKeyId"]
        self.session_credentials["SecretKey"] = session_credentials["SecretKey"]
        self.session_credentials["SessionToken"] = session_credentials["SessionToken"]
        this_session = boto3.session.Session(
            aws_access_key_id=self.session_credentials["AccessKeyId"],
            aws_secret_access_key=self.session_credentials["SecretKey"],
            aws_session_token=self.session_credentials["SessionToken"],
        )
        try:
            self.iam_resource = this_session.resource("iam", region_name=self.region)
            self.dynamodb = this_session.resource("dynamodb", region_name=self.region)
            self.table = self.dynamodb.Table("tag_tamer_roles")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to access these resources"
                )
            else:
                self.my_status.error()

    # Return the list of IAM Roles for the specified path prefix
    def get_roles(self, path_prefix):
        roles_inventory = list()
        try:
            raw_roles_inventory = self.iam_resource.roles.filter(PathPrefix=path_prefix)
            for raw_role in raw_roles_inventory:
                roles_inventory.append(raw_role.role_name)

            roles_inventory.sort(key=str.lower)
            self.my_status.success(message="IAM roles found!")
        except botocore.exceptions.ClientError as error:
            log.error(
                "Boto3 API returned error. function: {} - {}".format(
                    sys._getframe().f_code.co_name, error
                )
            )
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
                or error.response["Error"]["Code"] == "AccessDenied"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()

        return roles_inventory, self.my_status.get_status()

    # Get assigned tags for a specified role
    def get_role_tags(self, role_arn):
        tags = list()
        try:
            response = dict()
            response = self.table.get_item(
                Key={"role_arn": role_arn}, ProjectionExpression="tags"
            )
            tags = response["Item"]["tags"]
            self.my_status.success(message="IAM roles & associated tags found!")
        except botocore.exceptions.ClientError as error:
            log.error(
                "Boto3 API returned error. function: {} - {}".format(
                    sys._getframe().f_code.co_name, error
                )
            )
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
                or error.response["Error"]["Code"] == "AccessDenied"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()

        return tags, self.my_status.get_status()

    # Create a new role to tags mapping
    def set_role_tags(self, role_name, tags):
        try:
            role = self.iam_resource.Role(role_name)
            put_item_response = self.table.put_item(
                Item={
                    "role_arn": role.arn,
                    "tags": tags,
                },
                ReturnValues="NONE",
            )
            self.my_status.success(message="IAM role tags updated!")
        except botocore.exceptions.ClientError as error:
            log.error(
                "Boto3 API returned error. function: {} - {}".format(
                    sys._getframe().f_code.co_name, error
                )
            )
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
                or error.response["Error"]["Code"] == "AccessDenied"
            ):
                self.my_status.error(
                    message="You are not authorized to update these resources"
                )
            else:
                self.my_status.error()

        return self.my_status.get_status()
