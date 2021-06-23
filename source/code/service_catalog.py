#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Getter & setter for AWS Service Catalog (SC) items.
# A Tag Group equals a group of SC TagOptions that all have the same Tag Key

# Import administrative functions
from admin import execution_status

# Import AWS module for python
import boto3
import botocore
from botocore import exceptions

# Import Collections module to manipulate dictionaries
import collections
from collections import defaultdict

# Import getter for TagOption Groups
import get_tag_groups
from get_tag_groups import get_tag_groups

# Import JSON parser
import json

# Import logging module
import logging

# Import Python's regex module to filter Boto3's API responses
import re

log = logging.getLogger(__name__)

# Define Service Catalog (SC) class to get/set items using Boto3
class service_catalog:

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
            self.service_catalog_client = this_session.client(
                "servicecatalog", region_name=self.region
            )
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

    # Method to create an SC TagOption & return the TagOption ID
    def create_sc_tag_option(self, tag_key, tag_value):
        self.my_status = execution_status()
        tag_option_id = ""
        try:
            sc_response = self.service_catalog_client.create_tag_option(
                Key=tag_key, Value=tag_value
            )
            tag_option_id = sc_response["TagOptionDetail"]["Id"]
            self.my_status.success(message="Tag option found!")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to update these resources"
                )
            else:
                self.my_status.error()

        return tag_option_id, self.my_status.get_status()

    # Method to update an SC TagOption & return the TagOption ID
    def update_sc_tag_option(self, tag_key, tag_value):
        self.my_status = execution_status()
        tag_option_id = ""
        try:
            sc_response = self.service_catalog_client.update_tag_option(
                Key=tag_key, Value=tag_value
            )
            tag_option_id = sc_response["TagOptionDetail"]["Id"]
            self.my_status.success(message="Tag option found!")
        except botocore.exceptions.ClientError as error:
            log.error('Boto3 API returned error: "%s"', error)
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to update these resources"
                )
            else:
                self.my_status.error()
        return tag_option_id, self.my_status.get_status()

    # Method to get all existing TagOptions from SC
    def get_sc_tag_options(self, **kwargs):
        self.my_status = execution_status()
        sc_response = dict()
        try:
            if kwargs.get("key"):
                sc_response = self.service_catalog_client.list_tag_options(
                    Filters={"Key": kwargs.get("key")}
                )
            else:
                sc_response = self.service_catalog_client.list_tag_options()
            self.my_status.success(message="Service Catalog Tag options found!")
        except botocore.exceptions.ClientError as error:
            log.error('Boto3 API returned error: "%s"', error)
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()
        return sc_response, self.my_status.get_status()

    # Method to get all existing SC product template ID's & names
    def get_sc_product_templates(self):
        self.my_status = execution_status()
        sc_prod_templates_ids_names = dict()
        try:
            sc_response = self.service_catalog_client.search_products_as_admin(
                SortBy="Title", SortOrder="ASCENDING"
            )
            log.debug('The sc_response is: "%s"', sc_response)
            sc_product_templates = list()
            sc_product_templates = sc_response.get("ProductViewDetails")
            for template in sc_product_templates:
                if not re.search("^AWS", template["ProductViewSummary"].get("Owner")):
                    sc_prod_templates_ids_names[
                        template["ProductViewSummary"].get("ProductId")
                    ] = template["ProductViewSummary"].get("Name")
            self.my_status.success(message="Service Catalog product templates found!")
        except botocore.exceptions.ClientError as error:
            log.error('Boto3 API returned error: "%s"', error)
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()
        return sc_prod_templates_ids_names, self.my_status.get_status()

    # Method to assign a Tag Group (TG) to an SC product_template
    def assign_tg_sc_product_template(
        self, tag_group_name, sc_product_template_id, **session_credentials
    ):
        self.my_status = execution_status()
        all_sc_tag_options = dict()
        tag_group_contents = dict()
        this_sc_tag_option_values_ids = dict()

        # Instantiate a service catalog class instance
        sc_instance = service_catalog(self.region, **session_credentials)

        # Get the key & values list for the requested Tag Group
        tag_group = get_tag_groups(self.region, **session_credentials)
        (
            tag_group_contents,
            tag_group_execution_status,
        ) = tag_group.get_tag_group_key_values(tag_group_name)

        # Get the dictionary of current SC TagOptions
        all_sc_tag_options, sc_tag_execution_status = sc_instance.get_sc_tag_options(
            key=tag_group_contents["tag_group_key"]
        )

        # Get the TagOption ID's of all SC TagOptions that have the same key as the Tag Group parameter
        # If there's a key match, remember the corresponding value to determine if any Tag Group values are missing from SC
        for sc_tag_option in all_sc_tag_options["TagOptionDetails"]:
            if sc_tag_option["Key"] == tag_group_contents["tag_group_key"]:
                this_sc_tag_option_values_ids[sc_tag_option["Value"]] = sc_tag_option[
                    "Id"
                ]

        # Delete Service Catalog TagOptions values that are not included in selected Tag Group
        if this_sc_tag_option_values_ids:
            temp_tag_option_values_ids = this_sc_tag_option_values_ids.copy()
            for value, option_id in temp_tag_option_values_ids.items():
                if value not in tag_group_contents["tag_group_values"]:
                    try:
                        response = self.service_catalog_client.disassociate_tag_option_from_resource(
                            ResourceId=sc_product_template_id, TagOptionId=option_id
                        )
                        response = self.service_catalog_client.delete_tag_option(
                            Id=option_id
                        )
                        this_sc_tag_option_values_ids.pop(value)
                        self.my_status.success(
                            message="Service Catalog TagOption deleted!"
                        )
                    except botocore.exceptions.ClientError as error:
                        log.error('Boto3 API returned error: "%s"', error)
                        if (
                            error.response["Error"]["Code"] == "AccessDeniedException"
                            or error.response["Error"]["Code"]
                            == "UnauthorizedOperation"
                        ):
                            self.my_status.error(
                                message="You are not authorized to update these resources"
                            )
                        elif (
                            error.response["Error"]["Code"] == "ResourceInUseException"
                        ):
                            self.my_status.warning(
                                message='The TagOption Key: "'
                                + tag_group_contents["tag_group_key"]
                                + '" and Value: "'
                                + value
                                + '" is in use on another Product Template.'
                            )
                        else:
                            self.my_status.error()
                else:
                    self.my_status.success()

        # Create SC TagOptions for the selected Tag Group's values if value is not already an SC TagOption
        for value in tag_group_contents["tag_group_values"]:
            if value not in this_sc_tag_option_values_ids:
                (
                    tag_option_id,
                    tag_option_id_execution_status,
                ) = sc_instance.create_sc_tag_option(
                    tag_group_contents["tag_group_key"], value
                )
                this_sc_tag_option_values_ids[value] = tag_option_id

        product_template_details = dict()
        try:
            product_template_details = (
                self.service_catalog_client.describe_product_as_admin(
                    Id=sc_product_template_id
                )
            )
            self.my_status.success()
            current_status = self.my_status.get_status()
            if current_status["alert_level"] == "success":
                self.my_status.success(
                    message="Service Catalog product template found!"
                )
        except botocore.exceptions.ClientError as error:
            log.error('Boto3 API returned error: "%s"', error)
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()

        existing_prod_template_tag_options = list()
        existing_prod_template_tag_options = product_template_details.get("TagOptions")

        existing_product_template_tag_option_ids = list()

        for tag_option in existing_prod_template_tag_options:
            existing_product_template_tag_option_ids.append(tag_option.get("Id"))

        # Assign Tag value in the Tag Group to the specified SC product template if not already assigned
        for value, to_id in this_sc_tag_option_values_ids.items():
            if to_id not in existing_product_template_tag_option_ids:
                try:
                    sc_response = (
                        self.service_catalog_client.associate_tag_option_with_resource(
                            ResourceId=sc_product_template_id, TagOptionId=to_id
                        )
                    )
                    self.my_status.success()
                    current_status = self.my_status.get_status()
                    if current_status["alert_level"] == "success":
                        self.my_status.success(
                            message="New Tag Option associated with Service Catalog product!"
                        )
                except botocore.exceptions.ClientError as error:
                    log.error('Boto3 API returned error: "%s"', error)
                    if (
                        error.response["Error"]["Code"] == "AccessDeniedException"
                        or error.response["Error"]["Code"] == "UnauthorizedOperation"
                    ):
                        self.my_status.error(
                            message="You are not authorized to update these resources"
                        )
                    else:
                        self.my_status.error()

        # Return updated dictionary of TagOption keys & values for the SC product template
        product_template_details.clear()
        try:
            product_template_details = (
                self.service_catalog_client.describe_product_as_admin(
                    Id=sc_product_template_id
                )
            )
            self.my_status.success()
            current_status = self.my_status.get_status()
            if current_status["alert_level"] == "success":
                self.my_status.success(
                    message="Service Catalog product template found!"
                )
        except botocore.exceptions.ClientError as error:
            log.error('Boto3 API returned error: "%s"', error)
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()

        existing_prod_template_tag_options.clear()
        existing_prod_template_tag_options = product_template_details["TagOptions"]

        existing_tag_option_keys_values = defaultdict(list)
        for tag_option in existing_prod_template_tag_options:
            existing_tag_option_keys_values[tag_option["Key"]].append(
                tag_option["Value"]
            )

        return existing_tag_option_keys_values, self.my_status.get_status()