#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Getters & Setters for AWS Lambda function resource tags
#  This class supports the main "resources_tags" class
# Included class & methods
# class - lambda_resources_tags
#  method - get_lambda_names_ids
#  method - get_lambda_resources_tags
#  method - get_lambda_tag_keys
#  method - get_lambda_tag_values
#  method - set_lambda_resources_tags

# Import administrative functions
from admin import execution_status

# Import AWS module for python
import boto3, botocore
from botocore import exceptions

# Import collections to use ordered dictionaries for storage
from collections import OrderedDict

# Import logging module
import logging

# Import Python's regex module to filter Boto3's API responses
import re

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)

# Define resources_tags class to get/set resources & their assigned tags
class lambda_resources_tags:

    # Class constructor
    def __init__(self, resource_type, region):
        self.resource_type = resource_type
        self.region = region

    # Returns a filtered list of all resource names & ID's for the resource type specified
    def get_lambda_names_ids(self, filter_tags, **session_credentials):
        my_status = execution_status()
        self.filter_tags = filter_tags
        tag_key1_state = True if self.filter_tags.get("tag_key1") else False
        tag_value1_state = True if self.filter_tags.get("tag_value1") else False
        tag_key2_state = True if self.filter_tags.get("tag_key2") else False
        tag_value2_state = True if self.filter_tags.get("tag_value2") else False
        if not self.filter_tags.get("conjunction"):
            self.filter_tags["conjunction"] = "AND"
        resource_inventory = dict()

        self.session_credentials = dict()
        self.session_credentials = session_credentials

        if session_credentials.get("multi_account_role_session"):
            client = session_credentials["multi_account_role_session"].client(
                self.resource_type, region_name=self.region
            )
        else:
            this_session = boto3.session.Session(
                aws_access_key_id=self.session_credentials.get("AccessKeyId"),
                aws_secret_access_key=self.session_credentials.get("SecretKey"),
                aws_session_token=self.session_credentials.get("SessionToken"),
            )
            client = this_session.client(self.resource_type, region_name=self.region)

        def _intersection_union_invalid(tag_dict, function_name, function_arn):
            resource_inventory[
                "No matching resources found"
            ] = "No matching resources found"

        if self.filter_tags.get("conjunction") == "AND":

            def _intersection_tfff(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key1") in tag_dict:
                    resource_inventory[function_arn] = function_name

            def _intersection_fftf(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key2") in tag_dict:
                    resource_inventory[function_arn] = function_name

            def _intersection_fftt(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key2") in tag_dict:
                    if tag_dict.get(
                        self.filter_tags.get("tag_key2")
                    ) == self.filter_tags.get("tag_value2"):
                        resource_inventory[function_arn] = function_name

            def _intersection_ttff(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key1") in tag_dict:
                    if tag_dict.get(
                        self.filter_tags.get("tag_key1")
                    ) == self.filter_tags.get("tag_value1"):
                        resource_inventory[function_arn] = function_name

            def _intersection_tftf(tag_dict, function_name, function_arn):
                if (
                    self.filter_tags.get("tag_key1") in tag_dict
                    and self.filter_tags.get("tag_key2") in tag_dict
                ):
                    resource_inventory[function_arn] = function_name

            def _intersection_tftt(tag_dict, function_name, function_arn):
                if (
                    self.filter_tags.get("tag_key1") in tag_dict
                    and self.filter_tags.get("tag_key2") in tag_dict
                ):
                    if tag_dict.get(
                        self.filter_tags.get("tag_key2")
                    ) == self.filter_tags.get("tag_value2"):
                        resource_inventory[function_arn] = function_name

            def _intersection_tttf(tag_dict, function_name, function_arn):
                if (
                    self.filter_tags.get("tag_key1") in tag_dict
                    and self.filter_tags.get("tag_key2") in tag_dict
                ):
                    if tag_dict.get(
                        self.filter_tags.get("tag_key1")
                    ) == self.filter_tags.get("tag_value1"):
                        resource_inventory[function_arn] = function_name

            def _intersection_tttt(tag_dict, function_name, function_arn):
                if (
                    self.filter_tags.get("tag_key1") in tag_dict
                    and self.filter_tags.get("tag_key2") in tag_dict
                ):
                    if tag_dict.get(
                        self.filter_tags.get("tag_key1")
                    ) == self.filter_tags.get("tag_value1"):
                        if tag_dict.get(
                            self.filter_tags.get("tag_key2")
                        ) == self.filter_tags.get("tag_value2"):
                            resource_inventory[function_arn] = function_name

            def _intersection_ffff(tag_dict, function_name, function_arn):
                resource_inventory[function_arn] = function_name

            # "AND" Truth table check for tag_key1, tag_value1, tag_key2, tag_value2
            intersection_combos = {
                (False, False, False, True): _intersection_union_invalid,
                (False, True, False, False): _intersection_union_invalid,
                (False, True, False, True): _intersection_union_invalid,
                (True, False, False, True): _intersection_union_invalid,
                (True, True, False, True): _intersection_union_invalid,
                (False, True, True, False): _intersection_union_invalid,
                (False, False, True, False): _intersection_fftf,
                (False, False, True, True): _intersection_fftt,
                (True, False, False, False): _intersection_tfff,
                (True, True, False, False): _intersection_ttff,
                (True, False, True, False): _intersection_tftf,
                (True, False, True, True): _intersection_tftt,
                (True, True, True, False): _intersection_tttf,
                (True, True, True, True): _intersection_tttt,
                (False, False, False, False): _intersection_ffff,
            }

            try:
                # Get all the Lambda functions in the region
                my_functions = client.list_functions()
                for item in my_functions["Functions"]:
                    try:
                        # Get all the tags for a given Lambda function
                        response = client.list_tags(Resource=item["FunctionArn"])
                        if not response.get("Tags") and (
                            self.filter_tags.get("tag_key1") == "<No tags applied>"
                            or self.filter_tags.get("tag_key2") == "<No tags applied>"
                        ):
                            resource_inventory[item["FunctionArn"]] = item[
                                "FunctionName"
                            ]
                        else:
                            intersection_combos[
                                (
                                    tag_key1_state,
                                    tag_value1_state,
                                    tag_key2_state,
                                    tag_value2_state,
                                )
                            ](
                                response.get("Tags"),
                                item["FunctionName"],
                                item["FunctionArn"],
                            )

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

        if self.filter_tags.get("conjunction") == "OR":

            def _union_tfff_tftf_fftf(tag_dict, function_name, function_arn):
                if (
                    self.filter_tags.get("tag_key1") in tag_dict
                    or self.filter_tags.get("tag_key2") in tag_dict
                ):
                    resource_inventory[function_arn] = function_name

            def _union_tttf(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key1") in tag_dict:
                    if tag_dict[
                        self.filter_tags.get("tag_key1")
                    ] == self.filter_tags.get("tag_value1"):
                        resource_inventory[function_arn] = function_name
                elif self.filter_tags.get("tag_key2") in tag_dict:
                    resource_inventory[function_arn] = function_name

            def _union_tftt(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key2") in tag_dict:
                    if tag_dict[
                        self.filter_tags.get("tag_key2")
                    ] == self.filter_tags.get("tag_value2"):
                        resource_inventory[function_arn] = function_name
                elif self.filter_tags.get("tag_key1") in tag_dict:
                    resource_inventory[function_arn] = function_name

            def _union_fftt(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key2") in tag_dict:
                    if tag_dict[
                        self.filter_tags.get("tag_key2")
                    ] == self.filter_tags.get("tag_value2"):
                        resource_inventory[function_arn] = function_name

            def _union_ttff(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key1") in tag_dict:
                    if tag_dict[
                        self.filter_tags.get("tag_key1")
                    ] == self.filter_tags.get("tag_value1"):
                        resource_inventory[function_arn] = function_name

            def _union_tttt(tag_dict, function_name, function_arn):
                if self.filter_tags.get("tag_key1") in tag_dict:
                    if tag_dict[
                        self.filter_tags.get("tag_key1")
                    ] == self.filter_tags.get("tag_value1"):
                        resource_inventory[function_arn] = function_name
                elif self.filter_tags.get("tag_key2") in tag_dict:
                    if tag_dict[
                        self.filter_tags.get("tag_key2")
                    ] == self.filter_tags.get("tag_value2"):
                        resource_inventory[function_arn] = function_name

            def _union_ffff(tag_dict, function_name, function_arn):
                resource_inventory[function_arn] = function_name

            # "OR" Truth table check for tag_key1, tag_value1, tag_key2, tag_value2
            or_combos = {
                (False, False, False, True): _intersection_union_invalid,
                (False, True, False, False): _intersection_union_invalid,
                (False, True, False, True): _intersection_union_invalid,
                (False, True, True, True): _intersection_union_invalid,
                (True, True, False, True): _intersection_union_invalid,
                (False, False, True, False): _union_tfff_tftf_fftf,
                (False, False, True, True): _union_fftt,
                (True, False, False, False): _union_tfff_tftf_fftf,
                (True, False, True, False): _union_tfff_tftf_fftf,
                (True, False, True, True): _union_tftt,
                (True, True, False, False): _union_ttff,
                (True, True, True, False): _union_tttf,
                (True, True, True, True): _union_tttt,
                (False, False, False, False): _union_ffff,
            }

            try:
                # Get all the Lambda functions in the region
                my_functions = client.list_functions()
                for item in my_functions["Functions"]:
                    try:
                        # Get all the tags for a given Lambda function
                        response = client.list_tags(Resource=item["FunctionArn"])
                        if not response.get("Tags") and (
                            self.filter_tags.get("tag_key1") == "<No tags applied>"
                            or self.filter_tags.get("tag_key2") == "<No tags applied>"
                        ):
                            resource_inventory[item["FunctionArn"]] = item[
                                "FunctionName"
                            ]
                        else:
                            or_combos[
                                (
                                    tag_key1_state,
                                    tag_value1_state,
                                    tag_key2_state,
                                    tag_value2_state,
                                )
                            ](
                                response.get("Tags"),
                                item["FunctionName"],
                                item["FunctionArn"],
                            )

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
        my_status = execution_status()
        # Instantiate dictionaries to hold resources & their tags
        tagged_resource_inventory = dict()
        self.session_credentials = dict()
        self.session_credentials = session_credentials

        if session_credentials.get("multi_account_role_session"):
            client = session_credentials["multi_account_role_session"].client(
                self.resource_type, region_name=self.region
            )
        else:
            this_session = boto3.session.Session(
                aws_access_key_id=self.session_credentials.get("AccessKeyId"),
                aws_secret_access_key=self.session_credentials.get("SecretKey"),
                aws_session_token=self.session_credentials.get("SessionToken"),
            )
            client = this_session.client(self.resource_type, region_name=self.region)

        try:
            if chosen_resources[0][0] != "No matching resources found":
                for resource_id_name in chosen_resources:
                    resource_tags = dict()
                    sorted_resource_tags = dict()
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
        my_status = execution_status()
        tag_keys_inventory = list()
        # Give users ability to find resources with no tags applied
        tag_keys_inventory.append("<No tags applied>")

        self.session_credentials = dict()
        self.session_credentials = session_credentials

        if session_credentials.get("multi_account_role_session"):
            client = session_credentials["multi_account_role_session"].client(
                self.resource_type, region_name=self.region
            )
        else:
            this_session = boto3.session.Session(
                aws_access_key_id=self.session_credentials.get("AccessKeyId"),
                aws_secret_access_key=self.session_credentials.get("SecretKey"),
                aws_session_token=self.session_credentials.get("SessionToken"),
            )
            client = this_session.client(self.resource_type, region_name=self.region)

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
        my_status = execution_status()
        tag_values_inventory = list()

        self.session_credentials = dict()
        self.session_credentials = session_credentials

        if session_credentials.get("multi_account_role_session"):
            client = session_credentials["multi_account_role_session"].client(
                self.resource_type, region_name=self.region
            )
        else:
            this_session = boto3.session.Session(
                aws_access_key_id=self.session_credentials.get("AccessKeyId"),
                aws_secret_access_key=self.session_credentials.get("SecretKey"),
                aws_session_token=self.session_credentials.get("SessionToken"),
            )
            client = this_session.client(self.resource_type, region_name=self.region)

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
        my_status = execution_status()
        resources_updated_tags = dict()
        tag_dict = dict()

        self.resources_to_tag = resources_to_tag
        self.chosen_tags = chosen_tags
        self.session_credentials = dict()
        self.session_credentials = session_credentials

        if session_credentials.get("multi_account_role_session"):
            client = session_credentials["multi_account_role_session"].client(
                self.resource_type, region_name=self.region
            )
        else:
            this_session = boto3.session.Session(
                aws_access_key_id=self.session_credentials.get("AccessKeyId"),
                aws_secret_access_key=self.session_credentials.get("SecretKey"),
                aws_session_token=self.session_credentials.get("SessionToken"),
            )
            client = this_session.client(self.resource_type, region_name=self.region)

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