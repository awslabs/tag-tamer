"""
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    PDX-License-Identifier: MIT-0
"""

import json
import logging

import boto3
import botocore

from admin import ExecutionStatus

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


# Define AWS Config class to get/set items using Boto3
class Config:
    """Getter & setter for AWS Config Rules"""

    # Class initializer
    def __init__(self, region, **session_credentials):
        self.region = region
        self.session_credentials = session_credentials

        if session_credentials.get("multi_account_role_session"):
            self.client = session_credentials["multi_account_role_session"].client(
                "config", region_name=self.region
            )
        else:
            this_session = boto3.session.Session(
                aws_access_key_id=self.session_credentials.get("AccessKeyId"),
                aws_secret_access_key=self.session_credentials.get("SecretKey"),
                aws_session_token=self.session_credentials.get("SessionToken"),
            )
            self.client = this_session.client("config", region_name=self.region)

    def get_config_rule(self, config_rule_name):
        """Get REQUIRED_TAGS Config Rule name & input parameters"""
        my_status = ExecutionStatus()
        required_tags_config_rules = {}
        try:
            response = self.client.describe_config_rules(
                ConfigRuleNames=[config_rule_name]
            )
            all_config_rules = response.get("ConfigRules")
            for rule in all_config_rules:
                if rule.get("Source").get("SourceIdentifier") == "REQUIRED_TAGS":
                    input_parameters_dict = json.loads(rule.get("InputParameters"))
                    required_tags_config_rules["ConfigRuleName"] = rule.get(
                        "ConfigRuleName"
                    )
                    if rule.get("Scope"):
                        required_tags_config_rules[
                            "ComplianceResourceTypes"
                        ] = rule.get("Scope").get("ComplianceResourceTypes")
                    for key, value in input_parameters_dict.items():
                        required_tags_config_rules[key] = value
                    input_parameters_dict.clear()
                    my_status.success(message='"required-tags" Config rules found!')
        except botocore.exceptions.ClientError as error:
            errorString = "Boto3 API returned error: {}"
            log.error(errorString.format(error))
            if (
                error.response["Error"]["Code"] == "AccessDeniedException"
                or error.response["Error"]["Code"] == "UnauthorizedOperation"
            ):
                my_status.error(
                    message="You are not authorized to view these resources"
                )
            else:
                my_status.error()
        return required_tags_config_rules, my_status.get_status()

    def get_config_rules_ids_names(self):
        """Get REQUIRED_TAGS Config Rule names & ID's"""
        my_status = ExecutionStatus()
        config_rules_ids_names = {}

        def _find_all_required_tags_config_rules(next_token=None):
            try:
                if next_token:
                    response = self.client.describe_config_rules(NextToken=next_token)
                else:
                    response = self.client.describe_config_rules()
                all_config_rules = response.get("ConfigRules")
                for configRule in all_config_rules:
                    if (
                        configRule.get("Source").get("SourceIdentifier")
                        == "REQUIRED_TAGS"
                    ):
                        config_rules_ids_names[
                            configRule.get("ConfigRuleId")
                        ] = configRule.get("ConfigRuleName")

                if config_rules_ids_names:
                    my_status.success(message='"required-tags" Config rules found!')
                else:
                    my_status.warning(message='No "required-tags" Config rules found!')
                if response.get("NextToken"):
                    _find_all_required_tags_config_rules(
                        next_token=response.get("NextToken")
                    )

            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error: {}"
                log.error(errorString.format(error))
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()
                config_rules_ids_names.clear()

        _find_all_required_tags_config_rules(next_token=None)

        return config_rules_ids_names, my_status.get_status()

    def set_config_rules(
        self, tag_groups_keys_values, config_rule_id, config_rule_name
    ):
        """Set REQUIRED_TAGS Config Rule"""
        my_status = ExecutionStatus()
        if len(tag_groups_keys_values) and config_rule_id:
            # convert selected Tag Groups into JSON for Boto3 input to
            # this Config Rule's underlying Lambda :
            input_parameters_json = json.dumps(tag_groups_keys_values)
            (
                config_rule_current_parameters,
                config_rule_current_parameters_execution_status,
            ) = self.get_config_rule(config_rule_name)
            try:
                if config_rule_current_parameters.get("ComplianceResourceTypes"):
                    self.client.put_config_rule(
                        ConfigRule={
                            "ConfigRuleId": config_rule_id,
                            "Scope": {
                                "ComplianceResourceTypes": config_rule_current_parameters.get(
                                    "ComplianceResourceTypes"
                                )
                            },
                            "InputParameters": input_parameters_json,
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "REQUIRED_TAGS",
                            },
                        }
                    )
                else:
                    self.client.put_config_rule(
                        ConfigRule={
                            "ConfigRuleId": config_rule_id,
                            "InputParameters": input_parameters_json,
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "REQUIRED_TAGS",
                            },
                        }
                    )
                my_status.success(message='"required-tags" Config rules updated!')
                log.debug(
                    'REQUIRED_TAGS Config Rule "%s" updated with these parameters: "%s"',
                    config_rule_id,
                    input_parameters_json,
                )
            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error: {}"
                log.error(errorString.format(error))
                if (
                    error.response["Error"]["Code"] == "AccessDeniedException"
                    or error.response["Error"]["Code"] == "UnauthorizedOperation"
                ):
                    my_status.error(
                        message="You are not authorized to view these resources"
                    )
                else:
                    my_status.error()

        else:
            my_status.warning(
                message="Please select at least one Tag Group and Config rule."
            )

        return my_status.get_status()
