#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Getter & setter for AWS resources & tags.
#
# This file contains all getter & setter methods for Amazon EC2 instances, Amazon EBS volumes & Amazon S3 buckets
# This file also contains all method calls to all other Tag Tamer supported resources such as AWS EKS clusters & AWS Lambda functions
# Included class & methods:
# class - resources_tags
#  method - get_resources
#  method - get_resources_tags
#  method - get_tag_keys
#  method - get_tag_values
#  method - set_resources_tags

# Import administrative functions
from admin import execution_status

# Import AWS module for python
import boto3, botocore
from botocore import exceptions

# Import collections to use ordered dictionaries for storage
from collections import OrderedDict

# Impport csv to create output files
import csv

# Import AWS EKS clusters resources & tags getters & setters
from eks_clusters_tags import eks_clusters_tags

# Import AWS Lambda resources & tags getters & setters
from lambda_resources_tags import lambda_resources_tags

# Import Amazon Aurora DB resources & tags getters & setters
from aurora_db_resources_tags import aurora_db_resources_tags

# Import Amazon DynamoDB resources & tags getters & setters
from dynamodb_resources_tags import dynamodb_resources_tags

# Import Amazon ECR resources & tags getters & setters
from ecr_resources_tags import ecr_resources_tags

# Import AWS CodePipeline resources & tags getters & setters
from code_pipeline_tags import code_pipeline_tags

# Import AWS CodeCommit resources & tags getters & setters
from code_commit_tags import code_commit_tags

# Import Amazon RDS instances & tags getters & setters
from rds_resources_tags import rds_resources_tags

# Import Amazon Redshift Clusters & tags getters & setters
from redshift_cluster_tags import redshift_cluster_resources_tags

# Import logging module
import logging

# Import Python's regex module to filter Boto3's API responses
import re

# Import sys to return name of current function
import sys

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)

# Define resources_tags class to get/set resources & their assigned tags
class resources_tags:

    # Class constructor
    def __init__(self, resource_type, unit, region):
        # EBS uses the "ec2" Boto3 client
        # Both RDS instances & Aurora DB clusters use the "rds" Boto3 client
        if resource_type == "ebs":
            self.resource_type = "ec2"
        elif resource_type == "rdsInstances":
            self.resource_type = "rds"
        else:
            self.resource_type = resource_type
        self.unit = unit
        self.region = region

    # Purpose:  Returns a sorted list of resource tuples for the resource type & filter tags submitted
    #           Returns all resources for a give resource type if no filter tags submitted
    #           resource tuples are (resource-id, resource-name) if the name tag exists
    def get_resources(self, filter_tags, **session_credentials):
        my_status = execution_status()
        self.filter_tags = dict()
        self.filter_tags = filter_tags
        log.debug("The received filter tags are: {}".format(self.filter_tags))

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

        # Nested function to get resources that match user-selected tag keys & values
        def _get_filtered_resources(client_command):

            filters_list = list()

            # Issue Boto3 method using client, client command & filters list
            def _boto3_get_method():
                try:
                    if filters_list:
                        filtered_resources = getattr(client, client_command)(
                            Filters=filters_list
                        )
                    else:
                        filtered_resources = getattr(client, client_command)()
                    my_status.success(message="Resources Found!")
                    log.debug(
                        "The filtered resources are: {}".format(filtered_resources)
                    )
                    return filtered_resources

                except botocore.exceptions.ClientError as error:
                    errorString = "Boto3 API returned error. function: {} - {}"
                    log.error(errorString.format(sys._getframe().f_code.co_name, error))
                    if (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                        or error.response["Error"]["Code"] == "AccessDenied"
                    ):
                        my_status.error(
                            message="You are not authorized to view these resources"
                        )
                    else:
                        my_status.error()
                    filtered_resources = dict()
                    return filtered_resources

            ## Get all instance or volume resources that have no tags applied
            if (
                self.filter_tags.get("tag_key1") == "<No tags applied>"
                or self.filter_tags.get("tag_key2") == "<No tags applied>"
            ):
                filters_list.clear()
                requested_resources = _boto3_get_method()
                if self.unit == "instances":
                    if requested_resources.get("Reservations"):
                        for item in requested_resources["Reservations"]:
                            if item.get("Instances"):
                                untagged_resources = list()
                                for resource in item["Instances"]:
                                    # Untagged resources have no Tags attribute. Identify those & update list of instances
                                    if not resource.get("Tags"):
                                        untagged_resources.append(resource)
                                item["Instances"] = untagged_resources
                if self.unit == "volumes":
                    if requested_resources.get("Volumes"):
                        untagged_resources = list()
                        for resource in requested_resources["Volumes"]:
                            # Untagged resources have no Tags attribute
                            if not resource.get("Tags"):
                                untagged_resources.append(resource)
                        requested_resources["Volumes"] = untagged_resources
                returned_dict = dict()
                returned_dict["results_1"] = requested_resources
                return returned_dict

            # Add any selected tag keys and values to the AWS resource filter "filters_list"
            if self.filter_tags.get("conjunction") == "AND":
                if self.filter_tags.get("tag_key1"):
                    tag_dict = dict()
                    tag_value_list = list()
                    if self.filter_tags.get("tag_value1"):
                        tag_dict["Name"] = "tag:" + self.filter_tags.get("tag_key1")
                        tag_value_list.append(self.filter_tags.get("tag_value1"))
                    else:
                        tag_dict["Name"] = "tag-key"
                        tag_value_list.append(self.filter_tags.get("tag_key1"))
                    tag_dict["Values"] = tag_value_list
                    filters_list.append(tag_dict)
                if self.filter_tags.get("tag_key2"):
                    tag_dict = dict()
                    tag_value_list = list()
                    if self.filter_tags.get("tag_value2"):
                        tag_dict["Name"] = "tag:" + self.filter_tags.get("tag_key2")
                        tag_value_list.append(self.filter_tags.get("tag_value2"))
                    else:
                        tag_dict["Name"] = "tag-key"
                        tag_value_list.append(self.filter_tags.get("tag_key2"))
                    tag_dict["Values"] = tag_value_list
                    filters_list.append(tag_dict)

                requested_resources = _boto3_get_method()
                returned_dict = dict()
                returned_dict["results_1"] = requested_resources
                return returned_dict

            elif self.filter_tags.get("conjunction") == "OR":
                tag1_matching_resources = dict()
                tag2_matching_resources = dict()
                if self.filter_tags.get("tag_key1"):
                    tag_dict = dict()
                    tag_value_list = list()
                    if self.filter_tags.get("tag_value1"):
                        tag_dict["Name"] = "tag:" + self.filter_tags.get("tag_key1")
                        tag_value_list.append(self.filter_tags.get("tag_value1"))
                    else:
                        tag_dict["Name"] = "tag-key"
                        tag_value_list.append(self.filter_tags.get("tag_key1"))
                    tag_dict["Values"] = tag_value_list
                    filters_list.append(tag_dict)
                    tag1_matching_resources = _boto3_get_method()
                if self.filter_tags.get("tag_key2"):
                    filters_list = list()
                    tag_dict = dict()
                    tag_value_list = list()
                    if self.filter_tags.get("tag_value2"):
                        tag_dict["Name"] = "tag:" + self.filter_tags.get("tag_key2")
                        tag_value_list.append(self.filter_tags.get("tag_value2"))
                    else:
                        tag_dict["Name"] = "tag-key"
                        tag_value_list.append(self.filter_tags.get("tag_key2"))
                    tag_dict["Values"] = tag_value_list
                    filters_list.append(tag_dict)
                    tag2_matching_resources = _boto3_get_method()

                returned_dict = dict()
                # Place Boto3 filtered results into a dictionary return package
                if tag1_matching_resources and tag2_matching_resources:
                    returned_dict["results_1"] = tag1_matching_resources
                    returned_dict["results_2"] = tag2_matching_resources
                    return returned_dict
                elif tag1_matching_resources and not tag2_matching_resources:
                    returned_dict["results_1"] = tag1_matching_resources
                    return returned_dict
                elif not tag1_matching_resources and tag2_matching_resources:
                    returned_dict["results_1"] = tag2_matching_resources
                    return returned_dict
                else:
                    return None

            else:
                return None

        # Purpose:  Nested function to get all resources that have a tag with key 'name' or 'Name'
        #           and values are selected.  This is used to quickly gather the "name tags" of resources
        #           for easier identification in the Tag Tamer web UI
        def _get_named_resources(client_command):
            try:
                named_resources = getattr(client, client_command)(
                    Filters=[{"Name": "tag-key", "Values": ["name", "Name"]}]
                )
                my_status.success(message="Resources Found!")
                log.debug("The named resources are: {}".format(named_resources))
                return named_resources

            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error. function: {} - {}"
                log.error(errorString.format(sys._getframe().f_code.co_name, error))
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()
                named_resources = dict()
                return named_resources

        named_resource_inventory = dict()
        if self.unit == "instances":
            if self.filter_tags.get("tag_key1") or self.filter_tags.get("tag_key2"):
                try:
                    filtered_resources = _get_filtered_resources("describe_instances")
                    if len(filtered_resources):
                        for _, results in filtered_resources.items():
                            for item in results["Reservations"]:
                                for resource in item["Instances"]:
                                    named_resource_inventory[
                                        resource["InstanceId"]
                                    ] = "no name found"
                                    if resource.get("Tags"):
                                        for tag in resource["Tags"]:
                                            if tag["Key"].lower() == "name":
                                                named_resource_inventory[
                                                    resource["InstanceId"]
                                                ] = tag["Value"]
                        my_status.success(message="Resource tags found!")
                    else:
                        my_status.warning(message="No matching resources found")
                        named_resource_inventory[
                            "No matching resources found"
                        ] = "No matching resources found"
                except botocore.exceptions.ClientError as error:
                    log.error(
                        "Boto3 API returned error. function: {} - {}".format(
                            sys._getframe().f_code.co_name, error
                        )
                    )
                    named_resource_inventory[
                        "No matching resources found"
                    ] = "No matching resources found"
            else:
                try:
                    named_resources = _get_named_resources("describe_instances")
                    if len(named_resources):
                        if session_credentials.get("multi_account_role_session"):
                            selected_resource_type = session_credentials[
                                "multi_account_role_session"
                            ].resource(self.resource_type, region_name=self.region)
                        else:
                            selected_resource_type = this_session.resource(
                                self.resource_type, region_name=self.region
                            )
                        # Get all the resource ID's then add actual names to those having existing "name tags"
                        for resource in selected_resource_type.instances.all():
                            named_resource_inventory[resource.id] = "no name found"
                        for item in named_resources["Reservations"]:
                            for resource in item["Instances"]:
                                for tag in resource["Tags"]:
                                    if tag["Key"].lower() == "name":
                                        named_resource_inventory[
                                            resource["InstanceId"]
                                        ] = tag["Value"]
                        my_status.success(message="Resource tags found!")
                    else:
                        my_status.warning(message="No matching resources found")
                        named_resource_inventory[
                            "No matching resources found"
                        ] = "No matching resources found"
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
                        my_status.error(
                            message="You are not authorized to view these resources"
                        )
                    else:
                        my_status.error()

            named_resource_status = my_status.get_status()

        elif self.unit == "volumes":
            if self.filter_tags.get("tag_key1") or self.filter_tags.get("tag_key2"):
                try:
                    filtered_resources = _get_filtered_resources("describe_volumes")
                    if len(filtered_resources):
                        for _, results in filtered_resources.items():
                            for item in results["Volumes"]:
                                named_resource_inventory[
                                    item["VolumeId"]
                                ] = "no name found"
                                if item.get("Tags"):
                                    for tag in item["Tags"]:
                                        if tag["Key"].lower() == "name":
                                            named_resource_inventory[
                                                item["VolumeId"]
                                            ] = tag["Value"]
                        my_status.success(message="Resource tags found!")
                    else:
                        my_status.warning(message="No matching resources found")
                        named_resource_inventory[
                            "No matching resources found"
                        ] = "No matching resources found"
                except botocore.exceptions.ClientError as error:
                    log.error(
                        "Boto3 API returned error. function: {} - {}".format(
                            sys._getframe().f_code.co_name, error
                        )
                    )
                    named_resource_inventory[
                        "No matching resources found"
                    ] = "No matching resources found"
            else:
                try:
                    named_resources = _get_named_resources("describe_volumes")
                    if len(named_resources):
                        if session_credentials.get("multi_account_role_session"):
                            selected_resource_type = session_credentials[
                                "multi_account_role_session"
                            ].resource(self.resource_type, region_name=self.region)
                        else:
                            selected_resource_type = this_session.resource(
                                self.resource_type, region_name=self.region
                            )
                        # Get all the resource ID's then add actual names to those having existing "name tags"
                        for resource in selected_resource_type.volumes.all():
                            named_resource_inventory[resource.id] = "no name found"
                        for item in named_resources["Volumes"]:
                            for tag in item["Tags"]:
                                if tag["Key"].lower() == "name":
                                    named_resource_inventory[item["VolumeId"]] = tag[
                                        "Value"
                                    ]
                        my_status.success(message="Resources Found!")
                    else:
                        my_status.warning(message="No matching resources found")
                        named_resource_inventory[
                            "No matching resources found"
                        ] = "No matching resources found"
                except botocore.exceptions.ClientError as error:
                    errorString = "Boto3 API returned error. function: {} - {}"
                    log.error(errorString.format(sys._getframe().f_code.co_name, error))
                    named_resource_inventory[
                        "No matching resources found"
                    ] = "No matching resources found"
                    if (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                        or error.response["Error"]["Code"] == "AccessDenied"
                    ):
                        my_status.error(
                            message="You are not authorized to view these resources"
                        )
                    else:
                        my_status.error()

            named_resource_status = my_status.get_status()

        elif self.unit == "buckets":
            if session_credentials.get("multi_account_role_session"):
                selected_resource_type = session_credentials[
                    "multi_account_role_session"
                ].resource(self.resource_type, region_name=self.region)
            else:
                selected_resource_type = this_session.resource(
                    self.resource_type, region_name=self.region
                )
            if self.filter_tags.get("tag_key1") or self.filter_tags.get("tag_key2"):
                for resource in selected_resource_type.buckets.all():
                    log.debug("This bucket name is: {}".format(resource))
                    try:
                        response = client.get_bucket_tagging(Bucket=resource.name)
                        my_status.success(message="Resources Found!")
                    except botocore.exceptions.ClientError as error:
                        errorString = "Boto3 API returned error. function: {} - {}"
                        log.error(
                            errorString.format(sys._getframe().f_code.co_name, error)
                        )
                        if (
                            error.response["Error"]["Code"] == "AccessDeniedException"
                            or error.response["Error"]["Code"]
                            == "UnauthorizedOperation"
                            or error.response["Error"]["Code"] == "AccessDenied"
                        ):
                            my_status.error(
                                message="You are not authorized to view these resources"
                            )
                        else:
                            my_status.error()
                        response = dict()
                    if "TagSet" in response:
                        for tag in response["TagSet"]:
                            if self.filter_tags.get("tag_key1"):
                                if self.filter_tags.get("tag_value1"):
                                    if tag.get("Key") == self.filter_tags.get(
                                        "tag_key1"
                                    ) and tag.get("Value") == self.filter_tags.get(
                                        "tag_value1"
                                    ):
                                        named_resource_inventory[
                                            resource.name
                                        ] = resource.name
                                else:
                                    if tag.get("Key") == self.filter_tags.get(
                                        "tag_key1"
                                    ):
                                        named_resource_inventory[
                                            resource.name
                                        ] = resource.name
                            if self.filter_tags.get("tag_key2"):
                                if self.filter_tags.get("tag_value2"):
                                    if tag.get("Key") == self.filter_tags.get(
                                        "tag_key2"
                                    ) and tag.get("Value") == self.filter_tags.get(
                                        "tag_value2"
                                    ):
                                        named_resource_inventory[
                                            resource.name
                                        ] = resource.name
                                else:
                                    if tag.get("Key") == self.filter_tags.get(
                                        "tag_key2"
                                    ):
                                        named_resource_inventory[
                                            resource.name
                                        ] = resource.name
                    ## Get all buckets that have no tags applied
                    elif (
                        self.filter_tags.get("tag_key1") == "<No tags applied>"
                        or self.filter_tags.get("tag_key2") == "<No tags applied>"
                    ):
                        named_resource_inventory[resource.name] = resource.name
            else:
                try:
                    for resource in selected_resource_type.buckets.all():
                        named_resource_inventory[resource.name] = resource.name
                    my_status.success(message="Resources Found!")
                    log.debug(
                        "The buckets list is: {}".format(named_resource_inventory)
                    )
                except botocore.exceptions.ClientError as error:
                    errorString = "Boto3 API returned error. function: {} - {} - {}"
                    log.error(
                        errorString.format(
                            sys._getframe().f_code.co_name, self.unit, error
                        )
                    )
                    named_resource_inventory[
                        "No matching resources found"
                    ] = "No matching resources found"
                    if (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                        or error.response["Error"]["Code"] == "AccessDenied"
                    ):
                        my_status.error(
                            message="You are not authorized to view these resources"
                        )
                    else:
                        my_status.error()

            named_resource_status = my_status.get_status()

        elif self.unit == "functions":
            functions_inventory = lambda_resources_tags(self.resource_type, self.region)
            (
                named_resource_inventory,
                named_resource_status,
            ) = functions_inventory.get_lambda_names_ids(
                self.filter_tags, **self.session_credentials
            )

        elif self.unit == "pipelines":
            pipelines_inventory = code_pipeline_tags(self.resource_type, self.region)
            (
                named_resource_inventory,
                named_resource_status,
            ) = pipelines_inventory.get_code_pipeline_ids(
                self.filter_tags, **self.session_credentials
            )

        elif self.unit == "ecrrepositories":
            ecrrepositories_inventory = ecr_resources_tags(
                self.resource_type, self.region
            )
            (
                named_resource_inventory,
                named_resource_status,
            ) = ecrrepositories_inventory.get_ecr_names_ids(
                self.filter_tags, **self.session_credentials
            )

        elif self.unit == "repositories":
            repositories_inventory = code_commit_tags(self.resource_type, self.region)
            (
                named_resource_inventory,
                named_resource_status,
            ) = repositories_inventory.get_code_repository_ids(
                self.filter_tags, **self.session_credentials
            )

        elif self.unit == "clusters":
            clusters_inventory = eks_clusters_tags(self.resource_type, self.region)
            (
                named_resource_inventory,
                named_resource_status,
            ) = clusters_inventory.get_eks_clusters_ids(
                self.filter_tags, **self.session_credentials
            )

        elif self.unit == "rdsclusters":
            aurora_db_clusters_inventory = aurora_db_resources_tags(
                self.resource_type, self.region
            )
            (
                named_resource_inventory,
                named_resource_status,
            ) = aurora_db_clusters_inventory.get_aurora_db_names_ids(
                self.filter_tags, **self.session_credentials
            )
        elif self.unit == "rdsInstances":
            rds_instances_inventory = rds_resources_tags(
                self.resource_type, self.region
            )
            (
                named_resource_inventory,
                named_resource_status,
            ) = rds_instances_inventory.get_rds_names_ids(
                self.filter_tags, **self.session_credentials
            )
        elif self.unit == "redshiftclusters":
            redshift_clusters_inventory = redshift_cluster_resources_tags(
                self.resource_type, self.region
            )
            (
                named_resource_inventory,
                named_resource_status,
            ) = redshift_clusters_inventory.get_redshift_cluster_names_ids(
                self.filter_tags, **self.session_credentials
            )
        elif self.unit == "tables":
            dynamodb_tables_inventory = dynamodb_resources_tags(
                self.resource_type, self.region
            )
            (
                named_resource_inventory,
                named_resource_status,
            ) = dynamodb_tables_inventory.get_dynamodb_names_ids(
                self.filter_tags, **self.session_credentials
            )

        # Handle case where there are no resources meeting filter requirements
        if not len(named_resource_inventory):
            named_resource_inventory[
                "No matching resources found"
            ] = "No matching resources found"

        # Sort the resources based on the resource's name
        ordered_inventory = OrderedDict()
        ordered_inventory = sorted(
            named_resource_inventory.items(), key=lambda item: item[1]
        )
        # return ordered_inventory, my_status.get_status()
        return ordered_inventory, named_resource_status

    # method - download_csv
    # Creates a csv file of returned resource tag results for downloading
    def download_csv(
        self, file_open_method, account_number, region, inventory, user_name
    ):
        download_file = "./downloads/" + user_name + "-download.csv"
        file_contents = list()
        max_tags = 0
        for resource_id, tags in inventory.items():
            row = list()
            if len(tags) > max_tags:
                max_tags = len(tags)
            row.append(account_number)
            row.append(region)
            row.append(resource_id)
            for key, value in tags.items():
                row.append(key)
                row.append(value)
            file_contents.append(row)
        if file_open_method == "w":
            header_row = list()
            header_row.append("AWS Account Number")
            header_row.append("AWS Region")
            header_row.append("Resource ID")
            iterator = 1
            while iterator <= max_tags:
                tag_key_header = "Tag Key" + str(iterator)
                header_row.append(tag_key_header)
                tag_value_header = "Tag Value" + str(iterator)
                header_row.append(tag_value_header)
                iterator += 1
        with open(download_file, file_open_method, newline="") as file:
            writer = csv.writer(file)
            if file_open_method == "w":
                writer.writerow(header_row)
            writer.writerows(file_contents)
        file.close()
        # return download_file

    # Purpose:  Returns a nested dictionary of every resource & its key:value tags for the chosen resource type
    # Input arguments are Boto3 session credentials including list of chosen resource tuples & user name making request
    def get_resources_tags(self, **session_credentials):
        log.debug("The received session credentials are: %s", session_credentials)
        my_status = execution_status()
        returned_status = dict()
        # Instantiate dictionaries to hold resources & their tags
        tagged_resource_inventory = dict()
        sorted_tagged_resource_inventory = dict()

        self.chosen_resources = session_credentials.get("chosen_resources")
        self.region = session_credentials.get("region")

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

        # Interate through resources & inject resource ID's with user-defined tag key:value pairs per resource into a nested dictionary
        # indexed by resource ID
        if self.unit == "instances":
            try:
                if self.chosen_resources:
                    # client = this_session.client(self.resource_type, region_name=self.region)
                    for resource_id_name in self.chosen_resources:
                        response = client.describe_tags(
                            Filters=[
                                {"Name": "resource-id", "Values": [resource_id_name[0]]}
                            ]
                        )
                        resource_tags = dict()
                        sorted_resource_tags = dict()
                        if response.get("Tags"):
                            user_applied_tags = False
                            for tag in response["Tags"]:
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
                        sorted_resource_tags = OrderedDict(
                            sorted(resource_tags.items())
                        )
                        tagged_resource_inventory[
                            resource_id_name[0]
                        ] = sorted_resource_tags
                    my_status.success(message="Resources and tags found!")
                else:
                    my_status.error(
                        message="An error occurred.  Please contact your Tag Tamer administrator for assistance."
                    )
            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error. function: {} - {} - {}"
                log.error(
                    errorString.format(sys._getframe().f_code.co_name, self.unit, error)
                )
                tagged_resource_inventory["No matching resources found"] = {
                    "No Tags Found": "No Tags Found"
                }
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()
        elif self.unit == "volumes":
            try:
                if self.chosen_resources:
                    for resource_id_name in self.chosen_resources:
                        response = client.describe_tags(
                            Filters=[
                                {"Name": "resource-id", "Values": [resource_id_name[0]]}
                            ]
                        )
                        resource_tags = dict()
                        sorted_resource_tags = dict()
                        if response.get("Tags"):
                            user_applied_tags = False
                            for tag in response["Tags"]:
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

                        sorted_resource_tags = OrderedDict(
                            sorted(resource_tags.items())
                        )
                        tagged_resource_inventory[
                            resource_id_name[0]
                        ] = sorted_resource_tags
                    my_status.success(message="Resources and tags found!")
                else:
                    my_status.error(
                        message="An error occurred.  Please contact your Tag Tamer administrator for assistance."
                    )

            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error. function: {} - {} - {}"
                log.error(
                    errorString.format(sys._getframe().f_code.co_name, self.unit, error)
                )
                tagged_resource_inventory["No matching resources found"] = {
                    "No Tag Keys Found": "No Tag Values Found"
                }
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()
        elif self.unit == "buckets":
            try:
                if self.chosen_resources:
                    for resource_id_name in self.chosen_resources:
                        try:
                            response = client.get_bucket_tagging(
                                Bucket=resource_id_name[0]
                            )
                        except botocore.exceptions.ClientError as error:
                            errorString = "Boto3 API returned error. function: {} - bucket: {} - error message: {}"
                            if error.response["Error"]["Code"] == "NoSuchTagSet":
                                log.info(
                                    errorString.format(
                                        sys._getframe().f_code.co_name,
                                        resource_id_name[0],
                                        error,
                                    )
                                )
                                my_status.warning(message="No bucket tags found")
                            elif (
                                error.response["Error"]["Code"]
                                == "AccessDeniedException"
                                or error.response["Error"]["Code"]
                                == "UnauthorizedOperation"
                                or error.response["Error"]["Code"] == "AccessDenied"
                            ):
                                log.error(
                                    errorString.format(
                                        sys._getframe().f_code.co_name,
                                        resource_id_name[0],
                                        error,
                                    )
                                )
                                my_status.error(
                                    message="You are not authorized to view these resources"
                                )
                            else:
                                log.error(
                                    errorString.format(
                                        sys._getframe().f_code.co_name,
                                        resource_id_name[0],
                                        error,
                                    )
                                )
                                my_status.error()
                            response = dict()
                        resource_tags = dict()
                        sorted_resource_tags = dict()
                        if response.get("TagSet"):
                            user_applied_tags = False
                            for tag in response["TagSet"]:
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

                        sorted_resource_tags = OrderedDict(
                            sorted(resource_tags.items())
                        )
                        tagged_resource_inventory[
                            resource_id_name[0]
                        ] = sorted_resource_tags
                    my_status.success(message="Resources and tags found!")
                else:
                    my_status.error(
                        message="An error occurred.  Please contact your Tag Tamer administrator for assistance."
                    )

            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error. function: {} - {} - {}"
                log.error(
                    errorString.format(sys._getframe().f_code.co_name, self.unit, error)
                )
                tagged_resource_inventory["No matching resources found"] = {
                    "No Tag Keys Found": "No Tag Values Found"
                }
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()

        elif self.unit == "functions":
            functions_inventory = lambda_resources_tags(self.resource_type, self.region)
            (
                tagged_resource_inventory,
                returned_status,
            ) = functions_inventory.get_lambda_resources_tags(
                **self.session_credentials
            )

        elif self.unit == "pipelines":
            pipelines_inventory = code_pipeline_tags(self.resource_type, self.region)
            (
                tagged_resource_inventory,
                returned_status,
            ) = pipelines_inventory.get_pipeline_resources_tags(
                **self.session_credentials
            )

        elif self.unit == "ecrrepositories":
            ecrrepositories_inventory = ecr_resources_tags(
                self.resource_type, self.region
            )
            (
                tagged_resource_inventory,
                returned_status,
            ) = ecrrepositories_inventory.get_ecr_resources_tags(
                **self.session_credentials
            )

        elif self.unit == "repositories":
            repositories_inventory = code_commit_tags(self.resource_type, self.region)
            (
                tagged_resource_inventory,
                returned_status,
            ) = repositories_inventory.get_repository_resources_tags(
                **self.session_credentials
            )

        elif self.unit == "clusters":
            clusters_inventory = eks_clusters_tags(self.resource_type, self.region)
            (
                tagged_resource_inventory,
                returned_status,
            ) = clusters_inventory.get_eks_clusters_tags(**self.session_credentials)

        elif self.unit == "rdsclusters":
            aurora_db_clusters_inventory = aurora_db_resources_tags(
                self.resource_type, self.region
            )
            (
                tagged_resource_inventory,
                returned_status,
            ) = aurora_db_clusters_inventory.get_aurora_db_resources_tags(
                **self.session_credentials
            )
        elif self.unit == "rdsInstances":
            rds_instances_inventory = rds_resources_tags(
                self.resource_type, self.region
            )
            (
                tagged_resource_inventory,
                returned_status,
            ) = rds_instances_inventory.get_rds_resources_tags(
                **self.session_credentials
            )
        elif self.unit == "redshiftclusters":
            redshift_clusters_inventory = redshift_cluster_resources_tags(
                self.resource_type, self.region
            )
            (
                tagged_resource_inventory,
                returned_status,
            ) = redshift_clusters_inventory.get_redshift_cluster_resources_tags(
                **self.session_credentials
            )
        elif self.unit == "tables":
            dynamodb_tables_inventory = dynamodb_resources_tags(
                self.resource_type, self.region
            )
            (
                tagged_resource_inventory,
                returned_status,
            ) = dynamodb_tables_inventory.get_dynamodb_resources_tags(
                **self.session_credentials
            )
        sorted_tagged_resource_inventory = OrderedDict(
            sorted(tagged_resource_inventory.items())
        )

        if not returned_status:
            returned_status = my_status.get_status()

        return sorted_tagged_resource_inventory, returned_status

    # Purpose:  Getter method retrieves every tag:key for object's resource type
    # Input arguments are Boto3 session credentials
    def get_tag_keys(self, **session_credentials):
        my_status = execution_status()
        sorted_tag_keys_inventory = list()
        # Give users ability to find resources with no tags applied
        sorted_tag_keys_inventory.append("<No tags applied>")

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

        if self.unit == "instances":
            try:
                if session_credentials.get("multi_account_role_session"):
                    selected_resource_type = session_credentials[
                        "multi_account_role_session"
                    ].resource(self.resource_type, region_name=self.region)
                else:
                    selected_resource_type = this_session.resource(
                        self.resource_type, region_name=self.region
                    )
                item_count = False
                for item in selected_resource_type.instances.all():
                    if item.tags:
                        for tag in item.tags:
                            if not re.search("^aws:", tag["Key"]):
                                sorted_tag_keys_inventory.append(tag["Key"])
                                item_count = True
                                my_status.success(message="Tag keys found!")
                if not item_count:
                    sorted_tag_keys_inventory.append("No tags keys found!")
                    my_status.warning(message="No tag keys found!")
            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error. function: {} - {} - {}"
                log.error(
                    errorString.format(sys._getframe().f_code.co_name, self.unit, error)
                )
                sorted_tag_keys_inventory.append("")
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()
        elif self.unit == "volumes":
            try:
                if session_credentials.get("multi_account_role_session"):
                    selected_resource_type = session_credentials[
                        "multi_account_role_session"
                    ].resource(self.resource_type, region_name=self.region)
                else:
                    selected_resource_type = this_session.resource(
                        self.resource_type, region_name=self.region
                    )

                item_count = False
                for item in selected_resource_type.volumes.all():
                    if item.tags:
                        for tag in item.tags:
                            if not re.search("^aws:", tag["Key"]):
                                sorted_tag_keys_inventory.append(tag["Key"])
                                item_count = True
                                my_status.success(message="Tag keys found!")
                if not item_count:
                    sorted_tag_keys_inventory.append("No tags keys found!")
                    my_status.warning(message="No tag keys found!")

            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error. function: {} - {} - {}"
                log.error(
                    errorString.format(sys._getframe().f_code.co_name, self.unit, error)
                )
                sorted_tag_keys_inventory.append("No Tags Found")
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()
        elif self.unit == "buckets":
            if session_credentials.get("multi_account_role_session"):
                selected_resource_type = session_credentials[
                    "multi_account_role_session"
                ].resource(self.resource_type, region_name=self.region)
            else:
                selected_resource_type = this_session.resource(
                    self.resource_type, region_name=self.region
                )
            # boto_api_error = False
            item_count = False
            for item in list(selected_resource_type.buckets.all()):
                try:
                    if selected_resource_type.BucketTagging(item.name).tag_set:
                        for tag in selected_resource_type.BucketTagging(
                            item.name
                        ).tag_set:
                            if not re.search("^aws:", tag["Key"]):
                                sorted_tag_keys_inventory.append(tag["Key"])
                                item_count = True
                except botocore.exceptions.ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchTagSet":
                        errorString = "Boto3 API returned error. function: {} - bucket: {} - error message: {}"
                        log.info(
                            errorString.format(
                                sys._getframe().f_code.co_name, item.name, error
                            )
                        )
                    elif (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                        or error.response["Error"]["Code"] == "AccessDenied"
                    ):
                        errorString = "Boto3 API returned error. function: {} - bucket: {} - error message: {}"
                        log.error(
                            errorString.format(
                                sys._getframe().f_code.co_name, item.name, error
                            )
                        )
                    else:
                        errorString = (
                            "Boto3 API returned error. function: {} - error message: {}"
                        )
                        log.error(
                            errorString.format(sys._getframe().f_code.co_name, error)
                        )

            if item_count:
                my_status.success(message="Tag keys found!")
            else:
                my_status.warning(message="No tag keys found!")

        elif self.unit == "functions":
            functions_inventory = lambda_resources_tags(self.resource_type, self.region)
            (
                sorted_tag_keys_inventory,
                lambda_resources_status,
            ) = functions_inventory.get_lambda_tag_keys(**self.session_credentials)
            return sorted_tag_keys_inventory, lambda_resources_status

        elif self.unit == "pipelines":
            pipelines_inventory = code_pipeline_tags(self.resource_type, self.region)
            (
                sorted_tag_keys_inventory,
                code_pipeline_status,
            ) = pipelines_inventory.get_pipeline_tag_keys(**self.session_credentials)
            return sorted_tag_keys_inventory, code_pipeline_status

        elif self.unit == "ecrrepositories":
            ecrrepositories_inventory = ecr_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_keys_inventory,
                ecr_repository_status,
            ) = ecrrepositories_inventory.get_ecr_tag_keys(**self.session_credentials)
            return sorted_tag_keys_inventory, ecr_repository_status

        elif self.unit == "repositories":
            repositories_inventory = code_commit_tags(self.resource_type, self.region)
            (
                sorted_tag_keys_inventory,
                code_repository_status,
            ) = repositories_inventory.get_repository_tag_keys(
                **self.session_credentials
            )
            return sorted_tag_keys_inventory, code_repository_status

        elif self.unit == "clusters":
            clusters_inventory = eks_clusters_tags(self.resource_type, self.region)
            (
                sorted_tag_keys_inventory,
                eks_clusters_status,
            ) = clusters_inventory.get_eks_clusters_keys(**self.session_credentials)
            return sorted_tag_keys_inventory, eks_clusters_status

        elif self.unit == "rdsclusters":
            aurora_db_clusters_inventory = aurora_db_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_keys_inventory,
                aurora_db_resources_status,
            ) = aurora_db_clusters_inventory.get_aurora_db_tag_keys(
                **self.session_credentials
            )
            return sorted_tag_keys_inventory, aurora_db_resources_status

        elif self.unit == "rdsInstances":
            rds_instances_inventory = rds_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_keys_inventory,
                rds_resources_status,
            ) = rds_instances_inventory.get_rds_tag_keys(**self.session_credentials)
            return sorted_tag_keys_inventory, rds_resources_status

        elif self.unit == "redshiftclusters":
            redshift_clusters_inventory = redshift_cluster_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_keys_inventory,
                redshift_clusters_status,
            ) = redshift_clusters_inventory.get_redshift_cluster_tag_keys(
                **self.session_credentials
            )
            return sorted_tag_keys_inventory, redshift_clusters_status

        elif self.unit == "tables":
            dynamodb_tables_inventory = dynamodb_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_keys_inventory,
                dynamodb_tables_status,
            ) = dynamodb_tables_inventory.get_dynamodb_tag_keys(
                **self.session_credentials
            )
            return sorted_tag_keys_inventory, dynamodb_tables_status

        # Remove duplicate tags & sort
        sorted_tag_keys_inventory = list(set(sorted_tag_keys_inventory))
        sorted_tag_keys_inventory.sort(key=str.lower)

        return sorted_tag_keys_inventory, my_status.get_status()

    # Purpose:  Getter method retrieves every tag:value for object's resource type
    # Input arguments are Boto3 session credentials
    def get_tag_values(self, **session_credentials):
        my_status = execution_status()
        sorted_tag_values_inventory = list()

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

        if self.unit == "instances":
            try:
                if session_credentials.get("multi_account_role_session"):
                    selected_resource_type = session_credentials[
                        "multi_account_role_session"
                    ].resource(self.resource_type, region_name=self.region)
                else:
                    selected_resource_type = this_session.resource(
                        self.resource_type, region_name=self.region
                    )
                item_count = False
                for item in selected_resource_type.instances.all():
                    if item.tags:
                        for tag in item.tags:
                            if not re.search("^aws:", tag["Key"]) and tag["Value"]:
                                sorted_tag_values_inventory.append(tag["Value"])
                                item_count = True
                                my_status.success(message="Tag values found!")
                if not item_count:
                    sorted_tag_values_inventory.append("No tags values found!")
                    my_status.warning(message="No tag values found!")
            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error. function: {} - {} - {}"
                log.error(
                    errorString.format(sys._getframe().f_code.co_name, self.unit, error)
                )
                sorted_tag_values_inventory.append("No Tags Found")
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()
        elif self.unit == "volumes":
            try:
                if session_credentials.get("multi_account_role_session"):
                    selected_resource_type = session_credentials[
                        "multi_account_role_session"
                    ].resource(self.resource_type, region_name=self.region)
                else:
                    selected_resource_type = this_session.resource(
                        self.resource_type, region_name=self.region
                    )
                item_count = False
                for item in selected_resource_type.volumes.all():
                    if item.tags:
                        for tag in item.tags:
                            if not re.search("^aws:", tag["Key"]) and tag["Value"]:
                                sorted_tag_values_inventory.append(tag["Value"])
                                item_count = True
                                my_status.success(message="Tag values found!")
                if not item_count:
                    sorted_tag_values_inventory.append("No tags values found!")
                    my_status.warning(message="No tag values found!")
            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error. function: {} - {} - {}"
                log.error(
                    errorString.format(sys._getframe().f_code.co_name, self.unit, error)
                )
                sorted_tag_values_inventory.append("No Tags Found")
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()
        elif self.unit == "buckets":
            if session_credentials.get("multi_account_role_session"):
                selected_resource_type = session_credentials[
                    "multi_account_role_session"
                ].resource(self.resource_type, region_name=self.region)
            else:
                selected_resource_type = this_session.resource(
                    self.resource_type, region_name=self.region
                )
            item_count = False
            for item in list(selected_resource_type.buckets.all()):
                try:
                    if selected_resource_type.BucketTagging(item.name).tag_set:
                        for tag in selected_resource_type.BucketTagging(
                            item.name
                        ).tag_set:
                            if not re.search("^aws:", tag["Key"]) and tag["Value"]:
                                sorted_tag_values_inventory.append(tag["Value"])
                                item_count = True
                except botocore.exceptions.ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchTagSet":
                        errorString = "Boto3 API returned error. function: {} - bucket: {} - error message: {}"
                        log.info(
                            errorString.format(
                                sys._getframe().f_code.co_name, item.name, error
                            )
                        )
                    elif (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                        or error.response["Error"]["Code"] == "AccessDenied"
                    ):
                        errorString = "Boto3 API returned error. function: {} - bucket: {} - error message: {}"
                        log.error(
                            errorString.format(
                                sys._getframe().f_code.co_name, item.name, error
                            )
                        )
                    else:
                        errorString = (
                            "Boto3 API returned error. function: {} - error message: {}"
                        )
                        log.error(
                            errorString.format(sys._getframe().f_code.co_name, error)
                        )

            if item_count:
                my_status.success(message="Tag values found!")
            else:
                my_status.warning(message="No tag values found!")

        elif self.unit == "functions":
            functions_inventory = lambda_resources_tags(self.resource_type, self.region)
            (
                sorted_tag_values_inventory,
                lambda_resources_status,
            ) = functions_inventory.get_lambda_tag_values(**self.session_credentials)
            return sorted_tag_values_inventory, lambda_resources_status

        elif self.unit == "pipelines":
            pipelines_inventory = code_pipeline_tags(self.resource_type, self.region)
            (
                sorted_tag_values_inventory,
                code_pipeline_status,
            ) = pipelines_inventory.get_pipeline_tag_values(**self.session_credentials)
            return sorted_tag_values_inventory, code_pipeline_status

        elif self.unit == "ecrrepositories":
            ecrrepositories_inventory = ecr_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_values_inventory,
                ecr_repository_status,
            ) = ecrrepositories_inventory.get_ecr_tag_values(**self.session_credentials)
            return sorted_tag_values_inventory, ecr_repository_status

        elif self.unit == "repositories":
            repositories_inventory = code_commit_tags(self.resource_type, self.region)
            (
                sorted_tag_values_inventory,
                code_repository_status,
            ) = repositories_inventory.get_repository_tag_values(
                **self.session_credentials
            )
            return sorted_tag_values_inventory, code_repository_status

        elif self.unit == "clusters":
            clusters_inventory = eks_clusters_tags(self.resource_type, self.region)
            (
                sorted_tag_values_inventory,
                eks_clusters_status,
            ) = clusters_inventory.get_eks_clusters_values(**self.session_credentials)
            return sorted_tag_values_inventory, eks_clusters_status

        elif self.unit == "rdsclusters":
            aurora_db_clusters_inventory = aurora_db_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_values_inventory,
                aurora_db_resources_status,
            ) = aurora_db_clusters_inventory.get_aurora_db_tag_values(
                **self.session_credentials
            )
            return sorted_tag_values_inventory, aurora_db_resources_status

        elif self.unit == "rdsInstances":
            rds_instances_inventory = rds_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_values_inventory,
                rds_resources_status,
            ) = rds_instances_inventory.get_rds_tag_values(**self.session_credentials)
            return sorted_tag_values_inventory, rds_resources_status

        elif self.unit == "redshiftclusters":
            redshift_clusters_inventory = redshift_cluster_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_values_inventory,
                redshift_cluster_status,
            ) = redshift_clusters_inventory.get_redshift_cluster_tag_values(
                **self.session_credentials
            )
            return sorted_tag_values_inventory, redshift_cluster_status

        elif self.unit == "tables":
            dynamodb_tables_inventory = dynamodb_resources_tags(
                self.resource_type, self.region
            )
            (
                sorted_tag_values_inventory,
                dynamodb_tables_status,
            ) = dynamodb_tables_inventory.get_dynamodb_tag_values(
                **self.session_credentials
            )
            return sorted_tag_values_inventory, dynamodb_tables_status

        # Remove duplicate tags & sort
        sorted_tag_values_inventory = list(set(sorted_tag_values_inventory))
        sorted_tag_values_inventory.sort(key=str.lower)

        return sorted_tag_values_inventory, my_status.get_status()

    # Purpose:  Setter method to update tags on user-selected resources
    # Input arguments are Boto3 session credentials, list of resource ID's to tag & list of tag dictionaries
    def set_resources_tags(self, resources_to_tag, chosen_tags, **session_credentials):
        self.resources_to_tag = resources_to_tag
        self.chosen_tags = chosen_tags
        resources_updated_tags = dict()
        my_status = execution_status()

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

        if self.unit == "instances":
            try:
                if session_credentials.get("multi_account_role_session"):
                    selected_resource_type = session_credentials[
                        "multi_account_role_session"
                    ].resource(self.resource_type, region_name=self.region)
                else:
                    selected_resource_type = this_session.resource(
                        self.resource_type, region_name=self.region
                    )
                for resource_id in self.resources_to_tag:
                    resource_tag_list = []
                    instance = selected_resource_type.Instance(resource_id)
                    resource_tag_list = instance.create_tags(Tags=self.chosen_tags)
                resources_updated_tags[resource_id] = resource_tag_list
                my_status.success(message="Tags updated successfully!")
            except botocore.exceptions.ClientError as error:
                log.error(
                    "Boto3 API returned error: resource {} - {} - {}".format(
                        sys._getframe().f_code.co_name, resource_id, error
                    )
                )
                # log.error(error.response)
                resources_updated_tags["No Resources Found"] = "No Tags Applied"
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to modify these resources"
                    )
                else:
                    my_status.error()
            resources_status = my_status.get_status()

        elif self.unit == "volumes":
            try:
                if session_credentials.get("multi_account_role_session"):
                    selected_resource_type = session_credentials[
                        "multi_account_role_session"
                    ].resource(self.resource_type, region_name=self.region)
                else:
                    selected_resource_type = this_session.resource(
                        self.resource_type, region_name=self.region
                    )
                for resource_id in self.resources_to_tag:
                    resource_tag_list = []
                    volume = selected_resource_type.Volume(resource_id)
                    resource_tag_list = volume.create_tags(Tags=self.chosen_tags)
                resources_updated_tags[resource_id] = resource_tag_list
                my_status.success(message="Tags updated successfully!")
            except botocore.exceptions.ClientError as error:
                log.error(
                    "Boto3 API returned error: resource {} - {} - {}".format(
                        sys._getframe().f_code.co_name, resource_id, error
                    )
                )
                # log.error(error.response)
                resources_updated_tags["No Resources Found"] = "No Tags Applied"
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    or error.response["Error"]["Code"] == "AccessDenied"
                ):
                    my_status.error(
                        message="You are not authorized to modify these resources"
                    )
                else:
                    my_status.error()
            resources_status = my_status.get_status()

        elif self.unit == "buckets":
            for resource_id in self.resources_to_tag:
                tag_set_dict = dict()
                resource_tag_list = list()
                current_applied_tags = dict()
                try:
                    current_applied_tags = client.get_bucket_tagging(Bucket=resource_id)
                    log.debug(
                        "The existing tags for {} are {}".format(
                            resource_id, current_applied_tags
                        )
                    )
                except botocore.exceptions.ClientError as error:
                    errorString = "Boto3 API returned error: resource {} - {} - {}"
                    log.error(
                        errorString.format(
                            sys._getframe().f_code.co_name, resource_id, error
                        )
                    )
                    if (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                        or error.response["Error"]["Code"] == "AccessDenied"
                    ):
                        my_status.error(
                            message="You are not authorized to view these resources"
                        )
                    else:
                        my_status.error()
                if current_applied_tags.get("TagSet"):
                    for current_tag in current_applied_tags["TagSet"]:
                        for new_tag in self.chosen_tags:
                            if new_tag["Key"] != current_tag["Key"]:
                                self.chosen_tags.append(current_tag)
                tag_set_dict["TagSet"] = self.chosen_tags
                log.debug(
                    "The chosen tags for {} are {}".format(resource_id, tag_set_dict)
                )
                try:
                    if session_credentials.get("multi_account_role_session"):
                        selected_resource_type = session_credentials[
                            "multi_account_role_session"
                        ].resource(self.resource_type, region_name=self.region)
                    else:
                        selected_resource_type = this_session.resource(
                            self.resource_type, region_name=self.region
                        )
                    bucket_tagging = selected_resource_type.BucketTagging(resource_id)
                    resource_tag_list = bucket_tagging.put(Tagging=tag_set_dict)
                    resources_updated_tags[resource_id] = resource_tag_list
                    my_status.success(message="Tags updated successfully!")
                    log.debug(
                        "These tags are applied to the {} bucket: {}".format(
                            resource_id, resource_tag_list
                        )
                    )
                except botocore.exceptions.ClientError as error:
                    errorString = "Boto3 API returned error. function: {} - {} - {}"
                    log.error(
                        errorString.format(
                            sys._getframe().f_code.co_name, resource_id, error
                        )
                    )
                    # log.error(error.response)
                    resources_updated_tags["No Resources Found"] = "No Tags Applied"
                    if (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                        or error.response["Error"]["Code"] == "AccessDenied"
                    ):
                        my_status.error(
                            message="You are not authorized to modify these resources"
                        )
                    else:
                        my_status.error()
            resources_status = my_status.get_status()

        elif self.unit == "functions":
            functions_inventory = lambda_resources_tags(self.resource_type, self.region)
            resources_status = functions_inventory.set_lambda_resources_tags(
                self.resources_to_tag, self.chosen_tags, **self.session_credentials
            )

        elif self.unit == "pipelines":
            pipelines_inventory = code_pipeline_tags(self.resource_type, self.region)
            resources_status = pipelines_inventory.set_pipeline_resources_tags(
                self.resources_to_tag, self.chosen_tags, **self.session_credentials
            )

        elif self.unit == "ecrrepositories":
            ecrrepositories_inventory = ecr_resources_tags(
                self.resource_type, self.region
            )
            resources_status = ecrrepositories_inventory.set_ecr_resources_tags(
                self.resources_to_tag, self.chosen_tags, **self.session_credentials
            )

        elif self.unit == "repositories":
            repositories_inventory = code_commit_tags(self.resource_type, self.region)
            resources_status = repositories_inventory.set_repository_resources_tags(
                self.resources_to_tag, self.chosen_tags, **self.session_credentials
            )

        elif self.unit == "clusters":
            clusters_inventory = eks_clusters_tags(self.resource_type, self.region)
            resources_status = clusters_inventory.set_eks_clusters_tags(
                self.resources_to_tag, self.chosen_tags, **self.session_credentials
            )

        elif self.unit == "rdsclusters":
            aurora_db_clusters_inventory = aurora_db_resources_tags(
                self.resource_type, self.region
            )
            resources_status = (
                aurora_db_clusters_inventory.set_aurora_db_resources_tags(
                    self.resources_to_tag, self.chosen_tags, **self.session_credentials
                )
            )

        elif self.unit == "rdsInstances":
            rds_instances_inventory = rds_resources_tags(
                self.resource_type, self.region
            )
            resources_status = rds_instances_inventory.set_rds_resources_tags(
                self.resources_to_tag, self.chosen_tags, **self.session_credentials
            )

        elif self.unit == "redshiftclusters":
            redshift_clusters_inventory = redshift_cluster_resources_tags(
                self.resource_type, self.region
            )
            resources_status = (
                redshift_clusters_inventory.set_redshift_cluster_resources_tags(
                    resources_to_tag, chosen_tags, **self.session_credentials
                )
            )

        elif self.unit == "tables":
            dynamodb_tables_inventory = dynamodb_resources_tags(
                self.resource_type, self.region
            )
            resources_status = dynamodb_tables_inventory.set_dynamodb_resources_tags(
                resources_to_tag, chosen_tags, **self.session_credentials
            )

        return resources_status