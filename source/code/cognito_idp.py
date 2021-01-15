#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Purpose - functions to retrieve information regarding Amazon Cognito 
# user pools & users

# Import administrative functions
from admin import execution_status
# Import AWS module for python
import botocore
from botocore import exceptions
from botocore.exceptions import ClientError
import boto3
# Import logging module
import logging
# Import the systems module to get interpreter data
import sys

log = logging.getLogger(__name__)

# Function to return the authenticated user's user pool group ARN's
def get_user_group_arns(user_name, user_pool_id, region):
    try:
        my_status = execution_status()
        cognito_idp_groups = dict()
        cognito_idp_client = boto3.client('cognito-idp', region_name=region)
        cognito_idp_groups = cognito_idp_client.admin_list_groups_for_user(
            Username=user_name,
            UserPoolId=user_pool_id
        )
        # initially support one Cognito user pool group per user
        group_role_arn = cognito_idp_groups['Groups'][0]['RoleArn'] if cognito_idp_groups.get('Groups') else False
        my_status.success(message='Retrieved user permissions!')
    except botocore.exceptions.ClientError as error:
        log.error("Boto3 API returned error. function: {} - {}".format(sys._getframe().f_code.co_name, error))
        my_status.error()
        group_role_arn = False
    return group_role_arn

# Inputs: cognito_id_token = user's returned id_token JWT
def get_user_credentials(cognito_id_token, user_pool_id, identity_pool_id, region):
    my_status = execution_status()
    user_credentials = dict()
    idp_name = 'cognito-idp.' + region + '.amazonaws.com/' + user_pool_id

    try:
        cognito_identity_client = boto3.client('cognito-identity', region_name=region)
        identity_id_response = cognito_identity_client.get_id(
            IdentityPoolId=identity_pool_id,
            Logins={
                idp_name: cognito_id_token
            }
        )
        log.debug('function: {} - Received the Cognito identity'.format(sys._getframe().f_code.co_name))
        identity_id = identity_id_response['IdentityId']
        cognito_identity_response = cognito_identity_client.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={
                idp_name: cognito_id_token
            }
        )
        log.debug('function: {} - Received the Cognito credentials'.format(sys._getframe().f_code.co_name))
        user_credentials['AccessKeyId'] = cognito_identity_response['Credentials']['AccessKeyId']
        user_credentials['SecretKey'] = cognito_identity_response['Credentials']['SecretKey']
        user_credentials['SessionToken'] = cognito_identity_response['Credentials']['SessionToken']
        my_status.success(message='Retrieved user credentials!')
    except botocore.exceptions.ClientError as error:
            log.error("Boto3 API returned error. function: {} - {}".format(sys._getframe().f_code.co_name, error))
            my_status.error()
            user_credentials['AccessKeyId'] = None
            user_credentials['SecretKey'] = None
            user_credentials['SessionToken'] = None
    return user_credentials