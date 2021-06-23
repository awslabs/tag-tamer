#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Tag Tamer utility functions

# Import AWS modules for python
import boto3
import boto3.session
import botocore
from botocore import exceptions
from botocore.exceptions import ClientError

import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

# Import logging module
import logging

# Import the systems module to get interpreter data
import sys

log = logging.getLogger(__name__)

# Returns a list of all AWS regions
def get_aws_regions():
    my_session = boto3.session.Session(region_name="us-east-1")
    try:
        available_regions = my_session.get_available_regions(
            service_name="ec2", partition_name="aws"
        )
    except botocore.exceptions.ClientError as error:
        log.error(
            "Boto3 API returned error. function: {} - {}".format(
                sys._getframe().f_code.co_name, error
            )
        )
        available_regions = False
    return available_regions


# Return the Boto3 resource type & unit to the caller
def get_resource_type_unit(type):
    if type:
        if type == "codecommit":
            resource_type = "codecommit"
            unit = "repositories"
        elif type == "codepipeline":
            resource_type = "codepipeline"
            unit = "pipelines"
        elif type == "dynamodb":
            resource_type = "dynamodb"
            unit = "tables"
        elif type == "ebs":
            resource_type = "ebs"
            unit = "volumes"
        elif type == "ec2":
            resource_type = "ec2"
            unit = "instances"
        elif type == "ecr":
            resource_type = "ecr"
            unit = "ecrrepositories"
        elif type == "eks":
            resource_type = "eks"
            unit = "clusters"
        elif type == "lambda":
            resource_type = "lambda"
            unit = "functions"
        elif type == "rds":
            resource_type = "rds"
            unit = "rdsclusters"
        elif type == "rdsInstances":
            resource_type = "rdsInstances"
            unit = "rdsInstances"
        elif type == "redshift":
            resource_type = "redshift"
            unit = "redshiftclusters"
        elif type == "s3":
            resource_type = "s3"
            unit = "buckets"
        else:
            # If no resource type specified, set type to Amazon EC2
            resource_type = "ec2"
            unit = "instances"
        return resource_type, unit


# Decode & verify JWT claims
def verify_jwt(region, user_pool_id, app_client_id, token_type, token):
    this_region = region
    this_user_pool_id = user_pool_id
    this_token_type = token_type
    this_token = token
    this_app_client_id = app_client_id

    keys_url = "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(
        this_region, this_user_pool_id
    )

    with urllib.request.urlopen(keys_url) as f:
        response = f.read()
    keys = json.loads(response.decode("utf-8"))["keys"]
    headers = jwt.get_unverified_headers(this_token)
    kid = headers["kid"]
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]["kid"]:
            key_index = i
            break
    if key_index == -1:
        log.error("Public key not found in jwks.json")
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(this_token).rsplit(".", 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        log.error("Signature verification failed")
        return False
    log.info("Identity token signature successfully verified")
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(this_token)
    # additionally we can verify the token expiration
    if time.time() > claims["exp"]:
        log.error("Token is expired")
        return False
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if this_token_type == "access_token":
        if claims["client_id"] != this_app_client_id:
            log.error("Token was not issued for this audience")
            return False
    elif this_token_type == "id_token":
        if claims["aud"] != this_app_client_id:
            log.error("Token was not issued for this audience")
            return False
    else:
        return False
    # now we can use the claims
    return claims
