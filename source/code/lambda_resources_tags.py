#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Getters & Setters for AWS Lambda function resource tags
#  This class supports the main "resources_tags" class
# Included class & methods
# class - LambdaResourcesTags
#  method - get_lambda_names_ids
#  method - get_lambda_resources_tags
#  method - get_lambda_tag_keys
#  method - get_lambda_tag_values
#  method - set_lambda_resources_tags

import logging
import re
from collections import OrderedDict

import boto3
import botocore

from admin import ExecutionStatus, get_boto3_client_session
from tag_utilities import tag_filter_matcher, get_tag_filter_key_value_states

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


class LambdaResourcesTags:
    """Define resources_tags class to get/set resources & their assigned tags"""

    # Class constructor
    def __init__(self, resource_type, region):
        self.resource_type = resource_type
        self.region = region

    def get_lambda_names_ids(self, filter_tags, **session_credentials):
        """Returns a filtered list of all resource names & ID's for the resource type specified"""
        my_status = ExecutionStatus()
        (
            tag_key1_state,
            tag_value1_state,
            tag_key2_state,
            tag_value2_state,
        ) = get_tag_filter_key_value_states(filter_tags=filter_tags)
        if not filter_tags.get("conjunction"):
            filter_tags["conjunction"] = "AND"
        resource_inventory = {}

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Get all the Lambda functions in the region
            my_functions = client.list_functions()
            if my_functions.get("Functions"):
                for item in my_functions["Functions"]:
                    try:
                        # Get all the tags for a given Lambda function
                        response = client.list_tags(Resource=item["FunctionArn"])
                        if not response.get("Tags") and (
                            filter_tags.get("tag_key1") == "<No tags applied>"
                            or filter_tags.get("tag_key2") == "<No tags applied>"
                        ):
                            resource_inventory[item["FunctionArn"]] = item[
                                "FunctionName"
                            ]
                        elif response.get("Tags"):
                            tag_filter_matcher(
                                conjunction=filter_tags.get("conjunction"),
                                tag_key1_state=tag_key1_state,
                                tag_value1_state=tag_value1_state,
                                tag_key2_state=tag_key2_state,
                                tag_value2_state=tag_value2_state,
                                resource_inventory=resource_inventory,
                                filter_tags=filter_tags,
                                tag_dict=response.get("Tags"),
                                resource_name=item.get("FunctionName"),
                                resource_arn=item.get("FunctionArn"),
                            )
                        elif (
                            not tag_key1_state
                            and not tag_value1_state
                            and not tag_key2_state
                            and not tag_value2_state
                        ):
                            resource_inventory[item["FunctionArn"]] = item[
                                "FunctionName"
                            ]
                    except botocore.exceptions.ClientError as error:
                        log.error("Boto3 API returned error: {}".format(error))
                        if (
                            error.response["Error"]["Code"] == "AccessDeniedException"
                            or error.response["Error"]["Code"]
                            == "UnauthorizedOperation"
                        ):
                            my_status.error(
                                message="You are not authorized to view these resources"
                            )
                        else:
                            my_status.error()
                my_status.success(message="Resources and tags found!")
            # If no Lambda functions found
            else:
                my_status.warning(message="No resources and tags found!")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                my_status.error()

        return resource_inventory, my_status.get_status()

    # method - get_lambda_resources_tags
    # Returns a nested dictionary of every resource & its key:value tags for the chosen resource type
    # Input arguments - a list of resource id name lists input explicitly or part of argv dictionary
    def get_lambda_resources_tags(self, chosen_resources, **session_credentials):
        my_status = ExecutionStatus()
        # Instantiate dictionaries to hold resources & their tags
        tagged_resource_inventory = {}
        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            if chosen_resources:
                for resource_id_name in chosen_resources:
                    resource_tags = {}
                    function_arn = resource_id_name[0]
                    try:
                        # Get all the tags for a given Lambda function
                        response = client.list_tags(Resource=function_arn)
                        if response.get("Tags"):
                            user_applied_tags = False
                            for tag_key, tag_value in response["Tags"].items():
                                # Ignore tags applied by AWS which begin with "aws:"
                                if not re.search("^aws:", tag_key):
                                    resource_tags[tag_key] = tag_value
                                    user_applied_tags = True
                            if not user_applied_tags:
                                resource_tags[
                                    "No user-applied tag keys found"
                                ] = "No user-applied tag values found"
                        else:
                            resource_tags[
                                "No user-applied tag keys found"
                            ] = "No user-applied tag values found"
                    except botocore.exceptions.ClientError as error:
                        log.error("Boto3 API returned error: {}".format(error))
                        resource_tags["No Tags Found"] = "No Tags Found"
                        if (
                            error.response["Error"]["Code"] == "AccessDeniedException"
                            or error.response["Error"]["Code"]
                            == "UnauthorizedOperation"
                        ):
                            my_status.error(
                                message="You are not authorized to view these resources"
                            )
                        else:
                            my_status.error()
                    sorted_resource_tags = OrderedDict(sorted(resource_tags.items()))
                    tagged_resource_inventory[
                        resource_id_name[0]
                    ] = sorted_resource_tags
                    my_status.success(message="Resources and tags found!")
            else:
                tagged_resource_inventory["No Resource Found"] = {
                    "No tag keys found": "No tag values found"
                }
                my_status.warning(message="No AWS Lambda functions found!")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            tagged_resource_inventory["No Resource Found"] = {
                "No tag keys found": "No tag values found"
            }
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):

                my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                my_status.error()
        return tagged_resource_inventory, my_status.get_status()

    # method - get_lambda_tag_keys
    # Getter method retrieves every tag:key for object's resource type
    # No input arguments
    def get_lambda_tag_keys(self, **session_credentials):
        my_status = ExecutionStatus()
        tag_keys_inventory = []
        # Give users ability to find resources with no tags applied
        tag_keys_inventory.append("<No tags applied>")

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Get all the Lambda functions in the region
            my_functions = client.list_functions()
            for item in my_functions["Functions"]:
                function_arn = item["FunctionArn"]
                try:
                    # Get all the tags for a given Lambda function
                    response = client.list_tags(Resource=function_arn)
                    if len(response.get("Tags")):
                        # Add all tag keys to the list
                        for tag_key, _ in response["Tags"].items():
                            if not re.search("^aws:", tag_key):
                                tag_keys_inventory.append(tag_key)
                except botocore.exceptions.ClientError as error:
                    log.error("Boto3 API returned error: {}".format(error))
                    tag_keys_inventory.append("No tag keys found")
                    if (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    ):
                        my_status.error(
                            message="You are not authorized to view these resources"
                        )
                    else:
                        my_status.error()
            # Set success if tag values found else set warning
            if len(tag_keys_inventory):
                my_status.success(message="Tag keys found!")
            else:
                my_status.warning(message="No tag keys found for this resource type.")

        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            tag_keys_inventory.append("No tag keys found")
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                my_status.error()

        # Remove duplicate tags & sort
        tag_keys_inventory = list(set(tag_keys_inventory))
        tag_keys_inventory.sort(key=str.lower)

        return tag_keys_inventory, my_status.get_status()

    # method - get_lambda_tag_values
    # Getter method retrieves every tag:value for object's resource type
    # No input arguments
    def get_lambda_tag_values(self, **session_credentials):
        my_status = ExecutionStatus()
        tag_values_inventory = []

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Get all the Lambda functions in the region
            my_functions = client.list_functions()
            for item in my_functions["Functions"]:
                function_arn = item["FunctionArn"]
                try:
                    # Get all the tags for a given Lambda function
                    response = client.list_tags(Resource=function_arn)
                    if len(response.get("Tags")):
                        # Add all tag values to the list
                        for tag_key, tag_value in response["Tags"].items():
                            # Exclude any AWS-applied tags which begin with "aws:"
                            if not re.search("^aws:", tag_key) and tag_value:
                                tag_values_inventory.append(tag_value)
                except botocore.exceptions.ClientError as error:
                    log.error("Boto3 API returned error: {}".format(error))
                    if (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    ):
                        my_status.error(
                            message="You are not authorized to view these resources"
                        )
                    else:
                        my_status.error()
                    return tag_values_inventory, my_status.get_status()

            # Set success if tag values found else set warning
            if len(tag_values_inventory):
                my_status.success(message="Tag values found!")
            else:
                my_status.warning(message="No tag values found for this resource type.")

        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                my_status.error()
            return tag_values_inventory, my_status.get_status()

        # Remove duplicate tags & sort
        tag_values_inventory = list(set(tag_values_inventory))
        tag_values_inventory.sort(key=str.lower)

        return tag_values_inventory, my_status.get_status()

    # method - set_lambda_resources_tags
    # Setter method to update tags on user-selected resources
    # 2 inputs - list of resource Lambda arns to tag, list of individual tag key:value dictionaries
    def set_lambda_resources_tags(
        self, resources_to_tag, chosen_tags, **session_credentials
    ):
        my_status = ExecutionStatus()
        resources_updated_tags = {}
        tag_dict = {}

        self.resources_to_tag = resources_to_tag
        self.chosen_tags = chosen_tags
        self.session_credentials = {}
        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        # for Lambda Boto3 API convert list of tags dicts to single key:value tag dict
        for tag in self.chosen_tags:
            tag_dict[tag["Key"]] = tag["Value"]

        for resource_arn in self.resources_to_tag:
            try:
                response = client.tag_resource(Resource=resource_arn, Tags=tag_dict)
                my_status.success(message="Lambda function tags updated successfully!")
            except botocore.exceptions.ClientError as error:
                log.error("Boto3 API returned error: {}".format(error))
                resources_updated_tags["No Resources Found"] = "No Tags Applied"
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                ):
                    my_status.error(
                        message="You are not authorized to modify these resources"
                    )
                else:
                    my_status.error()
        return my_status.get_status()
