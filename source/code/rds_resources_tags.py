#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Getters & Setters for AWS RDS resource tags
#  This class supports the main "resources_tags" class
# Included class & methods
# class - RdsResourcesTags
#  method - get_rds_names_ids
#  method - get_rds_resources_tags
#  method - get_rds_tag_keys
#  method - get_rds_tag_values
#  method - set_rds_resources_tags

import logging
import re
from collections import OrderedDict

import boto3
import botocore

from admin import ExecutionStatus, get_boto3_client_session
from tag_utilities import tag_filter_matcher, get_tag_filter_key_value_states

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


class RdsResourcesTags:
    """Define resources_tags class to get/set resources & their assigned tags"""

    # Class constructor
    def __init__(self, resource_type, region):
        self.resource_type = resource_type
        self.region = region

    def get_rds_names_ids(self, filter_tags, **session_credentials):
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

        self.session_credentials = session_credentials

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Get all the resources in the region
            my_resources = client.describe_db_instances()
            if len(my_resources.get("DBInstances")):
                for item in my_resources["DBInstances"]:
                    if (
                        filter_tags.get("tag_key1") == "<No tags applied>"
                        or filter_tags.get("tag_key2") == "<No tags applied>"
                    ) and not len(item.get("TagList")):
                        resource_inventory[item["DBInstanceArn"]] = item[
                            "DBInstanceIdentifier"
                        ]
                    elif item.get("TagList"):
                        tag_dict = {}
                        for tag in item["TagList"]:
                            tag_dict[tag["Key"]] = tag["Value"]
                        tag_filter_matcher(
                            conjunction=filter_tags.get("conjunction"),
                            tag_key1_state=tag_key1_state,
                            tag_value1_state=tag_value1_state,
                            tag_key2_state=tag_key2_state,
                            tag_value2_state=tag_value2_state,
                            resource_inventory=resource_inventory,
                            filter_tags=filter_tags,
                            tag_dict=tag_dict,
                            resource_name=item.get("DBInstanceIdentifier"),
                            resource_arn=item.get("DBInstanceArn"),
                        )
                    elif (
                        not tag_key1_state
                        and not tag_value1_state
                        and not tag_key2_state
                        and not tag_value2_state
                    ):
                        resource_inventory[item["DBInstanceArn"]] = item[
                            "DBInstanceIdentifier"
                        ]
                my_status.success(message="Resources and tags found!")
            # If no RDS DB instances found
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

    # method - get_rds_resources_tags
    # Returns a nested dictionary of every resource & its key:value tags for the chosen resource type
    # List of chosen resources from get_rds_names_ids() & session credentials are arguments
    def get_rds_resources_tags(self, chosen_resources, **session_credentials):
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
                    resource_arn = resource_id_name[0]
                    try:
                        # Get all the tags for a given resource
                        response = client.list_tags_for_resource(
                            ResourceName=resource_arn
                        )
                        if response.get("TagList"):
                            user_applied_tags = False
                            for tag in response["TagList"]:
                                if not re.search("^aws:", tag["Key"]):
                                    resource_tags[tag["Key"]] = tag["Value"]
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
                        resource_tags["No tags found"] = "No tags found"
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
                    "No Tag Keys Found": "No Tag Values Found"
                }
                my_status.warning(message="No AWS resources found!")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            tagged_resource_inventory["No Resource Found"] = {
                "No Tag Keys Found": "No Tag Values Found"
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

    # method - get_rds_tag_keys
    # Getter method retrieves every tag:key for object's resource type
    # session credentials as the only input arguments
    def get_rds_tag_keys(self, **session_credentials):
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
            # Interate all the resources in the region
            my_resources = client.describe_db_instances()
            if len(my_resources["DBInstances"]) == 0:
                tag_keys_inventory.append("No tag keys found")
                my_status.warning(message="No Amazon RDS instances found!")
            else:
                for item in my_resources["DBInstances"]:
                    if item.get("TagList"):
                        # Add all tag keys to the list
                        for tag in item["TagList"]:
                            if not re.search("^aws:", tag["Key"]):
                                tag_keys_inventory.append(tag["Key"])
            # Set success if tag keys found else set warning
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

    # method - get_rds_tag_values
    # Getter method retrieves every tag:value for object's resource type
    # session credentials as the only input arguments
    def get_rds_tag_values(self, **session_credentials):
        my_status = ExecutionStatus()
        tag_values_inventory = []

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Interate all the resources in the region
            my_resources = client.describe_db_instances()
            if len(my_resources["DBInstances"]) == 0:
                # tag_values_inventory.append("No tag values found")
                my_status.warning(message="No Amazon RDS instances found!")
            else:
                for item in my_resources["DBInstances"]:
                    if len(item.get("TagList")):
                        # Add all tag keys to the list
                        for tag in item["TagList"]:
                            if not re.search("^aws:", tag["Value"]):
                                tag_values_inventory.append(tag["Value"])
            # Set success if tag values found else set warning
            if len(tag_values_inventory):
                my_status.success(message="Tag values found!")
            else:
                my_status.warning(message="No tag values found for this resource type.")

        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            # tag_values_inventory.append("No tag values found")
            tag_values_inventory.append("")
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

    # method - set_rds_resources_tags
    # Setter method to update tags on user-selected resources
    # 2 inputs - list of resource arns to tag, list of individual tag key:value dictionaries
    def set_rds_resources_tags(
        self, resources_to_tag, chosen_tags, **session_credentials
    ):
        my_status = ExecutionStatus()
        resources_updated_tags = {}

        self.resources_to_tag = resources_to_tag
        self.chosen_tags = chosen_tags
        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        for resource_arn in self.resources_to_tag:
            try:
                response = client.add_tags_to_resource(
                    ResourceName=resource_arn, Tags=self.chosen_tags
                )
                my_status.success(
                    message="Amazon RDS instance tags updated successfully!"
                )
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
