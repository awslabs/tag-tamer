#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Getters & Setters for AWS EKS Clusters resource tags
#  This class supports the main "resources_tags" class
# Included class & methods
# class - EksClustersTags
#  method - get_eks_clusters_ids
#  method - get_eks_clusters_tags
#  method - get_eks_clusters_keys
#  method - get_eks_clusters_values
#  method - set_eks_clusters_tags

import logging
import re
from collections import OrderedDict

import boto3
import botocore

from admin import ExecutionStatus, get_boto3_client_session
from tag_utilities import tag_filter_matcher, get_tag_filter_key_value_states

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


class EksClustersTags:
    """Define resources_tags class to get/set resources & their assigned tags"""

    # Class constructor
    def __init__(self, resource_type, region):
        self.resource_type = resource_type
        self.region = region

    def get_eks_clusters_ids(self, filter_tags, **session_credentials):
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
            # client = this_session.client(self.resource_type, region_name=self.region)
            # Get all the EKS Clusters in the region
            my_clusters = client.list_clusters()
            if my_clusters.get("clusters"):
                for item in my_clusters["clusters"]:
                    try:
                        eks_cluster_arn = client.describe_cluster(name=item)["cluster"][
                            "arn"
                        ]
                        # Get all the tags for a given EKS Cluster
                        response = client.list_tags_for_resource(
                            resourceArn=eks_cluster_arn
                        )
                        if (
                            filter_tags.get("tag_key1") == "<No tags applied>"
                            or filter_tags.get("tag_key2") == "<No tags applied>"
                        ) and not response.get("tags"):
                            resource_inventory[eks_cluster_arn] = item
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
                                resource_name=item,
                                resource_arn=eks_cluster_arn,
                            )
                        elif (
                            not tag_key1_state
                            and not tag_value1_state
                            and not tag_key2_state
                            and not tag_value2_state
                        ):
                            resource_inventory[eks_cluster_arn] = item
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
            # If no EKS cluster resources found
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

    # method - get_eks_clusters_tags
    # Returns a nested dictionary of every resource & its key:value tags for the chosen resource type
    # No input arguments
    def get_eks_clusters_tags(self, chosen_resources, **session_credentials):
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
                    eks_cluster_arn = client.describe_cluster(name=resource_id_name[1])[
                        "cluster"
                    ]["arn"]
                    try:
                        response = client.list_tags_for_resource(
                            resourceArn=eks_cluster_arn
                        )
                        if response.get("tags"):
                            user_applied_tags = False
                            for tag_key, tag_value in response["tags"].items():
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
                    tagged_resource_inventory[eks_cluster_arn] = sorted_resource_tags
                    my_status.success(message="Resources and tags found!")
            else:
                tagged_resource_inventory["No Resource Found"] = {
                    "No Tag Keys Found": "No Tag Values Found"
                }
                my_status.warning(message="No Amazon EKS clusters found!")
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

    # method - get_eks_clusters_keys
    # Getter method retrieves every tag:key for object's resource type
    # No input arguments
    def get_eks_clusters_keys(self, **session_credentials):
        my_status = ExecutionStatus()
        tag_keys_inventory = []

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Get all the EKS clusters in the region
            my_clusters = client.list_clusters()
            if len(my_clusters["clusters"]) == 0:
                my_status.warning(message="No Amazon EKS clusters found!")
            else:
                for item in my_clusters["clusters"]:
                    cluster_arn = client.describe_cluster(name=item)["cluster"]["arn"]
                    try:
                        # Get all the tags for a given EKS Cluster
                        response = client.list_tags_for_resource(
                            resourceArn=cluster_arn
                        )
                        if len(response.get("tags")):
                            # Add all tag keys to the list
                            for tag_key, _ in response["tags"].items():
                                if not re.search("^aws:", tag_key):
                                    tag_keys_inventory.append(tag_key)
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
                        return tag_keys_inventory, my_status.get_status()

            # Set success if tag values found else set warning
            if len(tag_keys_inventory):
                my_status.success(message="Tag keys found!")
            else:
                my_status.warning(message="No tag keys found for this resource type.")

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
            return tag_keys_inventory, my_status.get_status()

        # Remove duplicate tags & sort
        tag_keys_inventory = list(set(tag_keys_inventory))
        tag_keys_inventory.sort(key=str.lower)

        return tag_keys_inventory, my_status.get_status()

    # method - get_eks_clusters_values
    # Getter method retrieves every tag:value for object's resource type
    # No input arguments
    def get_eks_clusters_values(self, **session_credentials):
        my_status = ExecutionStatus()
        tag_values_inventory = []

        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        try:
            # Get all the EKS clusters in the region
            my_clusters = client.list_clusters()
            if len(my_clusters["clusters"]) == 0:
                # tag_values_inventory.append("No tag values found")
                my_status.warning(message="No Amazon EKS clusters found!")
            else:
                for item in my_clusters["clusters"]:
                    try:
                        response = client.describe_cluster(name=item)
                        cluster_arn = response["cluster"]["arn"]
                        try:
                            # Get all the tags for a given EKS Cluster
                            response = client.list_tags_for_resource(
                                resourceArn=cluster_arn
                            )
                            if len(response.get("tags")):
                                # Add all tag keys to the list
                                for tag_key, tag_value in response["tags"].items():
                                    # Exclude any AWS-applied tags which begin with "aws:"
                                    if not re.search("^aws:", tag_key):
                                        tag_values_inventory.append(tag_value)
                        except botocore.exceptions.ClientError as error:
                            log.error("Boto3 API returned error: {}".format(error))
                            if (
                                error.response["Error"]["Code"]
                                == "AccessDeniedException"
                                or error.response["Error"]["Code"]
                                == "UnauthorizedOperation"
                            ):
                                my_status.error(
                                    message="You are not authorized to view these resources"
                                )
                            else:
                                my_status.error()
                            return tag_values_inventory, my_status.get_status()
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

    # method - set_eks_clusters_tags
    # Setter method to update tags on user-selected resources
    # 2 inputs - list of resource EKS Cluster arns to tag, list of individual tag key:value dictionaries
    def set_eks_clusters_tags(
        self, resources_to_tag, chosen_tags, **session_credentials
    ):
        my_status = ExecutionStatus()
        resources_updated_tags = {}
        tag_dict = {}

        self.resources_to_tag = resources_to_tag
        self.chosen_tags = chosen_tags
        client, _ = get_boto3_client_session(
            session_credentials=session_credentials,
            resource_type=self.resource_type,
            region=self.region,
        )

        # for EKS Boto3 API convert list of tags dicts to single key:value tag dict
        for tag in self.chosen_tags:
            tag_dict[tag["Key"]] = tag["Value"]

        for resource_arn in self.resources_to_tag:
            try:
                response = client.tag_resource(resourceArn=resource_arn, tags=tag_dict)
                my_status.success(message="EKS cluster tags updated successfully!")
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
