"""
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: MIT-0
"""

import collections
import logging

import boto3
import botocore

from admin import ExecutionStatus

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


# Define get_tag_groups class
class GetTagGroups:
    """Getter delivering Tag Group attributes.  Returns output as dictionaries & lists"""

    # Class constructor
    def __init__(self, region, **session_credentials):
        self.my_status = ExecutionStatus()
        self.region = region

        this_session = boto3.session.Session(
            aws_access_key_id=session_credentials.get("AccessKeyId"),
            aws_secret_access_key=session_credentials.get("SecretKey"),
            aws_session_token=session_credentials.get("SessionToken"),
        )
        try:
            self.dynamodb = this_session.resource("dynamodb", region_name=self.region)
            self.table = self.dynamodb.Table("tag_tamer_tag_groups")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()

    def get_tag_group_names(self):
        """Returns a dictionary of actual_tag_group_name:actual_tag_group_key key:value pairs"""
        tag_group_names = {}
        sorted_tag_group_names = {}

        try:
            scan_response = self.table.scan(
                ProjectionExpression="key_name, tag_group_name"
            )
            log.debug("The DynamoDB scan response is: %s", scan_response)
            for item in scan_response["Items"]:
                tag_group_names[item["tag_group_name"]] = item["key_name"]
            self.my_status.success(message="Tag Groups found!")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            tag_group_names["No Tag Groups Found"] = "No Tag Groups Found"
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()

        sorted_tag_group_names = collections.OrderedDict(
            sorted(tag_group_names.items())
        )

        return sorted_tag_group_names, self.my_status.get_status()

    def get_tag_group_key_values(self, tag_group_name):
        """Returns a dictionary of tag_group_key:actual_tag_group_key
        & tag_group_values:list[actual_tag_group_values] for the specified Tag Group
        """
        tag_group_key_values = {}
        sorted_tag_group_values = []
        try:
            get_item_response = self.table.get_item(
                Key={"tag_group_name": tag_group_name}
            )
            if len(get_item_response["Item"]["tag_group_name"]):
                tag_group_key_values["tag_group_key"] = get_item_response["Item"][
                    "key_name"
                ]
                sorted_tag_group_values = get_item_response["Item"]["key_values"]
                sorted_tag_group_values.sort(key=str.lower)
                tag_group_key_values["tag_group_values"] = sorted_tag_group_values
            self.my_status.success(message="Tag Groups found!")
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            tag_group_key_values["tag_group_key"] = "No Tag Group Key Found"
            tag_group_key_values["tag_group_values"] = "No Tag Group Values Found"
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                self.my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                self.my_status.error()

        return tag_group_key_values, self.my_status.get_status()

    def get_all_tag_groups_key_values(self, region, **session_credentials):
        """Returns a list of 3-item lists where every 3-item list includes actual_tag_group_name, actual_tag_group_key
        & a list[actual_tag_group_values]
        """
        all_tag_groups_info = []

        inventory = GetTagGroups(region, **session_credentials)
        tag_groups_keys, status = inventory.get_tag_group_names()

        for tag_group_name, tag_group_key in tag_groups_keys.items():
            this_tag_group_info = []
            this_tag_group_key_values, status = inventory.get_tag_group_key_values(
                tag_group_name
            )
            this_tag_group_info.append(tag_group_name)
            this_tag_group_info.append(tag_group_key)
            this_tag_group_info.append(this_tag_group_key_values["tag_group_values"])
            all_tag_groups_info.append(this_tag_group_info)

        return all_tag_groups_info, status
