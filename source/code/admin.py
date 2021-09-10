"""
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: MIT-0

    Tag Tamer administrative functions
"""

import logging
from time import gmtime, strftime, time

import boto3
from boto3.session import Session
from botocore.exceptions import ClientError

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


def date_time_now():
    """Returns the date & current time"""
    time_string = strftime("%d-%B-%Y at %H:%M:%S UTC", gmtime())
    return time_string


class ExecutionStatus:
    """Returns the execution status of Tag Tamer functions
    alert_level variable aligns to getbootstrap_com/docs/4.5/components/alerts/
    """

    def __init__(self):
        self.status = {}

    def success(self, **kwargs):
        if kwargs.get("message"):
            self.status["status_message"] = kwargs["message"]
        else:
            self.status["status_message"] = "Your update was successful."
        self.status["alert_level"] = "success"

    def warning(self, **kwargs):
        if kwargs.get("message"):
            self.status["status_message"] = kwargs["message"]
        else:
            self.status[
                "status_message"
            ] = "Please contact your Tag Tamer administrator for assistance."
        self.status["alert_level"] = "warning"

    def error(self, **kwargs):
        if kwargs.get("message"):
            self.status["status_message"] = kwargs["message"]
        else:
            self.status[
                "status_message"
            ] = "An error occurred.  Please contact your Tag Tamer administrator for assistance."
        self.status["alert_level"] = "danger"

    def get_status(self):
        return self.status


def assume_role_multi_account(**kwargs):
    """Create & return a Boto3 session object for an IAM role assumed in another AWS account
    Inputs: IAM role ARN, user email, user name & user source IP address or source hostname all as keyword arguments
    """
    my_status = ExecutionStatus()
    this_session = boto3.session.Session(
        aws_access_key_id=kwargs["session_credentials"]["AccessKeyId"],
        aws_secret_access_key=kwargs["session_credentials"]["SecretKey"],
        aws_session_token=kwargs["session_credentials"]["SessionToken"],
    )
    sts_client = this_session.client("sts")

    if kwargs.get("user_id") and kwargs.get("user_email") and kwargs.get("user_source"):
        session_name = kwargs.get("user_id") + "-tag-tamer-session-" + str(time())
    else:
        log.error(
            'Failed to invoke "{}" on {}'.format(
                assume_role_multi_account.__name__, date_time_now()
            )
        )
        my_status.error()
        session_object = False
        return session_object

    try:
        response = sts_client.assume_role(
            RoleArn=kwargs.get("account_role_arn"), RoleSessionName=session_name
        )
        if len(response):
            session_object = Session(
                aws_access_key_id=response["Credentials"]["AccessKeyId"],
                aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
                aws_session_token=response["Credentials"]["SessionToken"],
            )
            log.info(
                '"{}" invoked "{}" on {} from location: "{}" using AWSAuth access key id: {} - SUCCESS'.format(
                    kwargs.get("user_email"),
                    assume_role_multi_account.__name__,
                    date_time_now(),
                    kwargs.get("user_source"),
                    response["Credentials"]["AccessKeyId"],
                )
            )
            my_status.success(
                message="Assumed multi-account role & created user session!"
            )
        else:
            log.error(
                '"{}" invoked "{}" on {} from location: "{}" - FAILURE'.format(
                    kwargs.get("user_email"),
                    assume_role_multi_account.__name__,
                    date_time_now(),
                    kwargs.get("user_source"),
                )
            )
            my_status.error(
                message="Failed to assume multi-account role & create user session!"
            )
            session_object = False
            return session_object

    except ClientError as error:
        log.error(
            "Boto3 API returned error. function: {} - {}".format(
                assume_role_multi_account.__name__, error
            )
        )
        my_status.error(
            message="Failed to assume multi-account role & create user session!"
        )
        session_object = False

    return session_object


def get_boto3_client_session(
    session_credentials=None, resource_type=None, region=None
):
    """Returns a Boto3 client & session based on supplied credentials"""
    if session_credentials.get("multi_account_role_session"):
        this_session = session_credentials.get("multi_account_role_session")
        client = session_credentials["multi_account_role_session"].client(
            resource_type, region_name=region
        )
    else:
        this_session = boto3.session.Session(
            aws_access_key_id=session_credentials.get("AccessKeyId"),
            aws_secret_access_key=session_credentials.get("SecretKey"),
            aws_session_token=session_credentials.get("SessionToken"),
        )
        client = this_session.client(resource_type, region_name=region)
    return client, this_session
