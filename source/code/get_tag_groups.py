#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Getter delivering Tag Group attributes.  Returns output as dictionaries & lists

# Import administrative functions
from admin import execution_status
# Import AWS module for python
import botocore
from botocore import exceptions
import boto3
# Import Collections module to manipulate dictionaries
import collections
# Import logging module
import logging

log = logging.getLogger(__name__)

# Define get_tag_groups class
class get_tag_groups:

    #Class constructor
    def __init__(self, region, **session_credentials):
        self.my_status = execution_status()
        self.tag_groups = {}
        self.region = region
        self.session_credentials = {}
        self.session_credentials['AccessKeyId'] = session_credentials['AccessKeyId']
        self.session_credentials['SecretKey'] = session_credentials['SecretKey']
        self.session_credentials['SessionToken'] = session_credentials['SessionToken']
        this_session = boto3.session.Session(
            aws_access_key_id=self.session_credentials['AccessKeyId'],
            aws_secret_access_key=self.session_credentials['SecretKey'],
            aws_session_token=self.session_credentials['SessionToken'])
        try:
            self.dynamodb = this_session.resource('dynamodb', region_name=self.region)
            self.table = self.dynamodb.Table('tag_tamer_tag_groups')
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            if error.response['Error']['Code'] == 'AccessDeniedException' or error.response['Error']['Code'] == 'UnauthorizedOperation':
                self.my_status.error(message='You are not authorized to view these resources')
            else:
                self.my_status.error()

    #Returns a dictionary of actual_tag_group_name:actual_tag_group_key key:value pairs
    def get_tag_group_names(self):
        tag_group_names={}
        sorted_tag_group_names={}
        
        try:
            scan_response = self.table.scan(
            ProjectionExpression="key_name, tag_group_name"
            )   
            log.debug("The DynamoDB scan response is: %s", scan_response)
            for item in scan_response["Items"]:
                tag_group_names[item["tag_group_name"]] = item["key_name"]
            self.my_status.success(message='Tag Groups found!')
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            tag_group_names["No Tag Groups Found"] = "No Tag Groups Found"
            if error.response['Error']['Code'] == 'AccessDeniedException' or error.response['Error']['Code'] == 'UnauthorizedOperation':
                self.my_status.error(message='You are not authorized to view these resources')
            else:
                self.my_status.error()
        
        sorted_tag_group_names = collections.OrderedDict(sorted(tag_group_names.items()))
        
        return sorted_tag_group_names, self.my_status.get_status() 
    
    #Returns a dictionary of tag_group_key:actual_tag_group_key
    #& tag_group_values:list[actual_tag_group_values] for the specified Tag Group
    def get_tag_group_key_values(self, tag_group_name):
        tag_group_key_values = dict()
        sorted_tag_group_values = list()
        try:
            get_item_response = self.table.get_item(Key={'tag_group_name': tag_group_name})
            if len(get_item_response["Item"]["tag_group_name"]):
                tag_group_key_values['tag_group_key'] = get_item_response["Item"]["key_name"]
                sorted_tag_group_values = get_item_response["Item"]["key_values"]
                sorted_tag_group_values.sort(key=str.lower)
                tag_group_key_values['tag_group_values'] = sorted_tag_group_values
            self.my_status.success(message='Tag Groups found!')
        except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error: {}".format(error))
            tag_group_key_values['tag_group_key'] = "No Tag Group Key Found"
            tag_group_key_values['tag_group_values'] = "No Tag Group Values Found" 
            if error.response['Error']['Code'] == 'AccessDeniedException' or error.response['Error']['Code'] == 'UnauthorizedOperation':
                self.my_status.error(message='You are not authorized to view these resources')
            else:
                self.my_status.error()
        
        return tag_group_key_values, self.my_status.get_status()

    #Returns a list of 3-item groups where every 3-item group includes actual_tag_group_name, actual_tag_group_key
    #& a list[actual_tag_group_values]
    def get_all_tag_groups_key_values(self, region, **session_credentials):
        all_tag_groups_info = list()

        inventory = get_tag_groups(region, **session_credentials)
        tag_groups_keys, status = inventory.get_tag_group_names()
        
        for tag_group_name, tag_group_key in tag_groups_keys.items():
            this_tag_group_info = list()
            this_tag_group_key_values, status = inventory.get_tag_group_key_values(tag_group_name)
            this_tag_group_info.append(tag_group_name)
            this_tag_group_info.append(tag_group_key)
            this_tag_group_info.append(this_tag_group_key_values['tag_group_values'])
            all_tag_groups_info.append(this_tag_group_info)

        return all_tag_groups_info, status