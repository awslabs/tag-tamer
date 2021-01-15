#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Getter & setter for AWS Config Rules

# Import administrative functions
from admin import execution_status
# Import AWS module for python
import botocore
from botocore import exceptions
import boto3
# Import JSON
import json
# Import logging module
import logging

log = logging.getLogger(__name__)

# Define AWS Config class to get/set items using Boto3
class config:
    
    #Class constructor
    def __init__(self, region, **session_credentials):
        self.region = region
        self.session_credentials = {}
        self.session_credentials['AccessKeyId'] = session_credentials['AccessKeyId']
        self.session_credentials['SecretKey'] = session_credentials['SecretKey']
        self.session_credentials['SessionToken'] = session_credentials['SessionToken']
        this_session = boto3.session.Session(
            aws_access_key_id=self.session_credentials['AccessKeyId'],
            aws_secret_access_key=self.session_credentials['SecretKey'],
            aws_session_token=self.session_credentials['SessionToken'])
        self.config_client = this_session.client('config', region_name=self.region)

    #Get REQUIRED_TAGS Config Rule name & input parameters
    def get_config_rule(self, config_rule_id):
        my_status = execution_status()
        required_tags_config_rules = dict()
        try:
            response = self.config_client.describe_config_rules()
            all_config_rules = dict()
            all_config_rules = response['ConfigRules']
            input_parameters_dict = dict()
            for rule in all_config_rules:
                if rule['Source']['SourceIdentifier'] == 'REQUIRED_TAGS':
                    input_parameters_dict = json.loads(rule['InputParameters'])
                    required_tags_config_rules['ConfigRuleName'] = rule['ConfigRuleName']
                    required_tags_config_rules['ComplianceResourceTypes'] = rule['Scope']['ComplianceResourceTypes']
                    for key, value in input_parameters_dict.items():
                        required_tags_config_rules[key] = value
                    input_parameters_dict.clear()
            my_status.success(message='\"required-tags\" Config rules found!')
        except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error: {}"
                log.error(errorString.format(error))
                if error.response['Error']['Code'] == 'AccessDeniedException' or \
                    error.response['Error']['Code'] == 'UnauthorizedOperation':
                    my_status.error(message='You are not authorized to view these resources')
                else:
                    my_status.error()
        return required_tags_config_rules, my_status.get_status()

    #Get REQUIRED_TAGS Config Rule names & ID's
    def get_config_rules_ids_names(self):
        my_status = execution_status()
        response = dict()
        all_config_rules = dict()
        config_rules_ids_names = dict()
        try:
            response = self.config_client.describe_config_rules()
            all_config_rules = response['ConfigRules']
            for configRule in all_config_rules:
                if configRule['Source']['SourceIdentifier'] == 'REQUIRED_TAGS':
                    config_rules_ids_names[configRule['ConfigRuleId']] = configRule['ConfigRuleName']
            if len(config_rules_ids_names):
                my_status.success(message='\"required-tags\" Config rules found!')
            else:
                my_status.warning(message='No \"required-tags\" Config rules found!')

        except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error: {}"
                log.error(errorString.format(error))
                if error.response['Error']['Code'] == 'AccessDeniedException' or \
                    error.response['Error']['Code'] == 'UnauthorizedOperation':
                    my_status.error(message='You are not authorized to view these resources')
                else:
                    my_status.error()
                config_rules_ids_names['No Config rules found'] = 'No Config rules found'
        
        return config_rules_ids_names, my_status.get_status()

    #Set REQUIRED_TAGS Config Rule
    def set_config_rules(self, tag_groups_keys_values, config_rule_id):
        my_status = execution_status()
        if len(tag_groups_keys_values) and config_rule_id:
            # convert selected Tag Groups into JSON for Boto3 input to
            # this Config Rule's underlying Lambda :
            input_parameters_json = json.dumps(tag_groups_keys_values)
            config_rule_current_parameters = dict()
            config_rule_current_parameters, config_rule_current_parameters_execution_status = self.get_config_rule(config_rule_id)
            try:
                self.config_client.put_config_rule(
                    ConfigRule={
                        'ConfigRuleId': config_rule_id,
                        'Scope': {
                            'ComplianceResourceTypes': config_rule_current_parameters['ComplianceResourceTypes']
                        },
                        'InputParameters': input_parameters_json,
                        'Source': {
                            'Owner': 'AWS',
                            'SourceIdentifier': 'REQUIRED_TAGS'
                        }    
                    }
                )
                my_status.success(message='\"required-tags\" Config rules updated!') 
                log.debug('REQUIRED_TAGS Config Rule \"%s\" updated with these parameters: \"%s\"', config_rule_id, input_parameters_json)
            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error: {}"
                log.error(errorString.format(error))
                if error.response['Error']['Code'] == 'AccessDeniedException' or \
                    error.response['Error']['Code'] == 'UnauthorizedOperation':
                    my_status.error(message='You are not authorized to view these resources')
                else:
                    my_status.error()

        else:
            my_status.warning(message="Please select at least one Tag Group and Config rule.")
        
        return my_status.get_status()