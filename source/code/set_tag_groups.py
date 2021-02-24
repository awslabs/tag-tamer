#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Setter updating tag groups in DynamoDB

# Import administrative functions
from admin import execution_status
# Import AWS module for python
import botocore
from botocore import exceptions
import boto3
from boto3.dynamodb.conditions import Key, Attr

# Import logging module
import logging
log = logging.getLogger(__name__)

#This class instantiates & updates Tag Tamer Tag Groups
class set_tag_group:

    #Class constructor
    def __init__(self, region, **session_credentials):
        self.my_status = execution_status()
        self.region = region
        self.tag_groups = dict()
        self.session_credentials = dict()
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
                    self.my_status.error(message='You are not authorized to access these resources')
            else:
                self.my_status.error()
    
    #Setter to instantiate a new Tag Group adding its tag key & range of tag values
    def create_tag_group(self, tag_group_name, tag_group_key_name, tag_group_value_options):
        if(len(tag_group_name) and len(tag_group_key_name)):
            try:
                put_item_response = self.table.put_item(
                    Item={
                        "tag_group_name": tag_group_name,
                        "resource_type": "all",
                        "key_name": tag_group_key_name,
                        "key_values": tag_group_value_options
                    },
                    ReturnValues='NONE',
                )
                log.debug('Successfully created Tag Group \"%s\" with Key \"%s\" & possible values \"%s\"', tag_group_name, tag_group_key_name, tag_group_value_options)
                self.my_status.success(message='Tag Group created!')
            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error: {}"
                log.error(errorString.format(error))
                put_item_response = errorString.format(error)
                if error.response['Error']['Code'] == 'AccessDeniedException' or error.response['Error']['Code'] == 'UnauthorizedOperation':
                    status_message = error.response['Error']['Code'] + ' - You are not authorized to create Tag Groups.'
                    self.my_status.error(message=status_message)
                else:
                    self.my_status.error(message=error.response['Error']['Message'])
        else:
            log.warning("Please provide a value for Tag Group name and Tag Key name")
            #put_item_response = "Please provide a value for Tag Group name and Tag Key name"
            self.my_status.error(message="Please provide a value for Tag Group name and Tag Key name")
        #return put_item_response
        return self.my_status.get_status()


    #Setter to update a tag's possible range of values
    def update_tag_group(self, tag_group_name, tag_group_key_name, tag_group_value_options):
        try:
            update_item_response = self.table.update_item(
                Key={
                    "tag_group_name": tag_group_name
                },
                UpdateExpression="set resource_type = :rt, key_name = :kn, key_values = :kv",
                ExpressionAttributeValues={
                    ":rt": "all",
                    ":kn": tag_group_key_name,
                    ":kv": tag_group_value_options
                },
                ReturnValues='NONE',
            )
            log.debug('Successfully updated Tag Group \"%s\" with Key \"%s\" to possible values \"%s\"', tag_group_name, tag_group_key_name, tag_group_value_options)
            self.my_status.success(message='Tag Group updated!')
        except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error: {}"
                log.error(errorString.format(error))
                update_item_response = errorString.format(error)
                if error.response['Error']['Code'] == 'AccessDeniedException' or error.response['Error']['Code'] == 'UnauthorizedOperation':
                    status_message = error.response['Error']['Code'] + ' - You are not authorized to update Tag Groups.'
                    self.my_status.error(message=status_message)
                else:
                    self.my_status.error(message=error.response['Error']['Message'])
        #return update_item_response
        return self.my_status.get_status()