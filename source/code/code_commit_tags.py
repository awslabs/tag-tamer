#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Getters & Setters for AWS CodeCommit repository resource tags
#  This class supports the main "resources_tags" class
# Included class & methods
# class - CodeCommitTags
#  method - get_code_repository_ids
#  method - get_repository_resources_tags
#  method - get_repository_tag_keys
#  method - get_repository_tag_values
#  method - set_repository_resources_tags

import logging
import re
from collections import OrderedDict

import boto3
import botocore

from admin import ExecutionStatus, get_boto3_client_session
from tag_utilities import tag_filter_matcher, get_tag_filter_key_value_states

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


# Define resources_tags class to get/set resources & their assigned tags
class CodeCommitTags:

    # Class constructor
    def __init__(self, resource_type, region):
        self.resource_type = resource_type
        self.region = region

    # Returns a filtered list of all resource names & ID's for the resource type specified
    def get_code_repository_ids(self, filter_tags, **session_credentials):
        my_status = ExecutionStatus()
        (
            tag_key1_state,
            tag_value1_state,
            tag_key2_state,
            tag_value2_state,
        ) = get_tag_filter_key_value_states(filter_tags=filter_tags)
        resource_inventory = {}

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Get all the CodeCommit repositories in the region
            my_repositories = client.list_repositories()
            if len(my_repositories.get("repositories")):
                for item in my_repositories["repositories"]:
                    try:
                        code_repository_arn = client.get_repository(
                            repositoryName=item["repositoryName"]
                        )["repositoryMetadata"]["Arn"]
                        # Get all the tags for a given Code repository
                        response = client.list_tags_for_resource(
                            resourceArn=code_repository_arn
                        )
                        if (
                            filter_tags.get("tag_key1") == "<No tags applied>"
                            or filter_tags.get("tag_key2") == "<No tags applied>"
                        ) and not response.get("tags"):
                            resource_inventory[code_repository_arn] = item[
                                "repositoryName"
                            ]
                        elif response.get("tags"):
                            tag_filter_matcher(
                                conjunction=filter_tags.get("conjunction"),
                                tag_key1_state=tag_key1_state,
                                tag_value1_state=tag_value1_state,
                                tag_key2_state=tag_key2_state,
                                tag_value2_state=tag_value2_state,
                                resource_inventory=resource_inventory,
                                filter_tags=filter_tags,
                                tag_dict=response.get("tags"),
                                resource_name=item.get("repositoryName"),
                                resource_arn=code_repository_arn,
                            )
                        elif (
                            not tag_key1_state
                            and not tag_value1_state
                            and not tag_key2_state
                            and not tag_value2_state
                        ):
                            resource_inventory[code_repository_arn] = item[
                                "repositoryName"
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
            # If no resources found
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

    # method - get_repository_resources_tags
    # Returns a nested dictionary of every resource & its key:value tags for the chosen resource type
    # input arguments - list of lists resource ID & resource name pairs and Boto3 session credentials as argv dictionary
    def get_repository_resources_tags(self, chosen_resources, **session_credentials):
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
                    sorted_resource_tags = {}
                    repository_arn = resource_id_name[0]
                    try:
                        # Get all the tags for a given Code repository
                        response = client.list_tags_for_resource(
                            resourceArn=repository_arn
                        )
                        if len(response.get("tags")):
                            for tag_key, tag_value in response["tags"].items():
                                if not re.search("^aws:", tag_key):
                                    resource_tags[tag_key] = tag_value
                        else:
                            resource_tags["No Tags Found"] = "No Tags Found"
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
                    "No Tags Found": "No Tags Found"
                }
                my_status.warning(message="No AWS CodeCommit repositories found!")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            tagged_resource_inventory["No Resource Found"] = {
                "No Tags Found": "No Tags Found"
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

    # method - get_repository_tag_keys
    # Getter method retrieves every tag:key for object's resource type
    # No input arguments
    def get_repository_tag_keys(self, **session_credentials):
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
            # Get all the Code repositories in the region
            my_repositories = client.list_repositories()
            if len(my_repositories.get("repositories")):
                for item in my_repositories["repositories"]:
                    code_repository_arn = client.get_repository(
                        repositoryName=item["repositoryName"]
                    )["repositoryMetadata"]["Arn"]
                    try:
                        # Get all the tags for a given Code repository
                        response = client.list_tags_for_resource(
                            resourceArn=code_repository_arn
                        )
                        try:
                            # Add all tag keys to the list
                            for tag_key, _ in response["tags"].items():
                                if not re.search("^aws:", tag_key):
                                    tag_keys_inventory.append(tag_key)
                            my_status.success(message="Resources and tags found!")
                        except Exception:
                            my_status.error(
                                message="You are not authorized to view these resources"
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
            # If no resources found
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

        # Remove duplicate tags & sort
        tag_keys_inventory = list(set(tag_keys_inventory))
        tag_keys_inventory.sort(key=str.lower)

        return tag_keys_inventory, my_status.get_status()

    # method - get_repository_tag_values
    # Getter method retrieves every tag:value for object's resource type
    # No input arguments
    def get_repository_tag_values(self, **session_credentials):
        my_status = ExecutionStatus()
        tag_values_inventory = []

        self.session_credentials = {}
        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Get all the Code repositories in the region
            my_repositories = client.list_repositories()
            if len(my_repositories.get("repositories")):
                for item in my_repositories["repositories"]:
                    code_repository_arn = client.get_repository(
                        repositoryName=item["repositoryName"]
                    )["repositoryMetadata"]["Arn"]
                    try:
                        # Get all the tags for a given Code repository
                        response = client.list_tags_for_resource(
                            resourceArn=code_repository_arn
                        )
                        try:
                            # Add all tag values to the list
                            for tag_key, tag_value in response["tags"].items():
                                # Exclude any AWS-applied tags which begin with "aws:"
                                if not re.search("^aws:", tag_key) and tag_value:
                                    tag_values_inventory.append(tag_value)
                        except Exception:
                            my_status.warning(
                                message="No tags found for this resource."
                            )
                    except botocore.exceptions.ClientError as error:
                        log.error("Boto3 API returned error: {}".format(error))
                        # tag_values_inventory.append("No tag values found")
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
            # If no resources found
            else:
                # tag_values_inventory.append("No tag values found")
                my_status.warning(message="No resources and tags found!")

        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            # tag_values_inventory.append("No tag values found")
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
        tag_values_inventory = list(set(tag_values_inventory))
        tag_values_inventory.sort(key=str.lower)

        return tag_values_inventory, my_status.get_status()

    # method - set_repository_resources_tags
    # Setter method to update tags on user-selected resources
    # 2 inputs - list of resource arns to tag, list of individual tag key:value dictionaries
    def set_repository_resources_tags(
        self, resources_to_tag, chosen_tags, **session_credentials
    ):
        my_status = ExecutionStatus()
        resources_updated_tags = {}
        tag_dict = {}
        self.chosen_tags = chosen_tags

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        # for Code repository Boto3 API convert list of tags dicts to single key:value tag dict
        for tag in self.chosen_tags:
            tag_dict[tag["Key"]] = tag["Value"]

        for resource_arn in resources_to_tag:
            try:
                response = client.tag_resource(resourceArn=resource_arn, tags=tag_dict)
                my_status.success(message="Tags updated successfully!")
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
