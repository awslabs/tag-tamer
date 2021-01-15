#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Tag Tamer administrative functions

from time import time, gmtime, strftime

# Return the date & current time
def date_time_now():
    now = gmtime()
    time_string = strftime("%d-%B-%Y at %H:%M:%S UTC", now)
    return time_string
  

# Define execution_status class to return the execution status of Tag Tamer functions
# alert_level variable aligns to getbootstrap_com/docs/4.5/components/alerts/
class execution_status:
    
        #Class constructor
        def __init__(self):
            self.status = dict()

        def success(self, **kwargs):
            if kwargs.get('message'):
                self.status['status_message'] = kwargs['message']
            else:
                self.status['status_message'] = 'Your update was successful.'
            self.status['alert_level'] = 'success'
        
        def warning(self, **kwargs):
            if kwargs.get('message'):
                self.status['status_message'] = kwargs['message']
            else:
                self.status['status_message'] = 'Please contact your Tag Tamer administrator.'
            self.status['alert_level'] = 'warning'

        def error(self, **kwargs):
            if kwargs.get('message'):
                self.status['status_message'] = kwargs['message']
            else:
                self.status['status_message'] = 'An error occurred.  Please contact your Tag Tamer administrator for assistance.'
            self.status['alert_level'] = 'danger'
        
        def get_status(self):
            return self.status
            