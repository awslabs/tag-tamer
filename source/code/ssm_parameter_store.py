#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Getter & setter for AWS SSM Parameter Store

import logging

import boto3
import botocore

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


class SsmParameterStore:
    """Define AWS SSM Parameter Store class to get/set items using Boto3"""

    # Class constructor
    def __init__(self, region):
        self.region = region
        self.ssm_client = boto3.client("ssm", region_name=self.region)

    def form_parameter_hierarchies(self, ssm_parameter_path, ssm_parameter_names):
        """List comprehension to create the fully qualified SSM parameter names"""
        parameter_list = [ssm_parameter_path + name for name in ssm_parameter_names]
        return parameter_list

    def ssm_get_parameter_details(self, ssm_parameter_path):
        """Argument: Path prefix for all SSM parameter name.  Example path prefix: /tag-tamer/
        Returns: SSM Parameter Dictionaries
        """
        ssm_parameters = {}

        def _get_parameter_response(**kwargs):
            try:
                if kwargs.get("next_token"):
                    response = self.ssm_client.get_parameters_by_path(
                        MaxResults=10,
                        NextToken=kwargs.get("next_token"),
                        Path=ssm_parameter_path,
                        Recursive=False,
                        WithDecryption=True,
                    )
                else:
                    response = self.ssm_client.get_parameters_by_path(
                        MaxResults=10,
                        Path=ssm_parameter_path,
                        Recursive=False,
                        WithDecryption=True,
                    )
                log.debug("The parameter response is: %s", response)
                for parameter in response["Parameters"]:
                    ssm_parameters[parameter["Name"]] = parameter["Value"]
                if response.get("NextToken"):
                    _get_parameter_response(next_token=response.get("NextToken"))
            except botocore.exceptions.ClientError as error:
                errorString = "Boto3 API returned error: {}"
                log.error(errorString.format(error))
            log.debug("The final parameter response is: %s", ssm_parameters)

        _get_parameter_response()
        parameter_dictionary = {}
        for name, value in ssm_parameters.items():
            # Remove the path prepending the SSM Parameter name
            name_components = name.split("/")
            short_parameter_name = name_components[-1]
            parameter_dictionary[short_parameter_name] = value
        log.debug("The returned parameter dictionary is: %s", parameter_dictionary)
        return parameter_dictionary
