#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Tag Tamer Admin UI

# Import administrative functions
from admin import date_time_now
# Import Collections module to manipulate dictionaries
import collections
from collections import defaultdict, OrderedDict
# Import getter functions for Amazon Cognito
from cognito_idp import get_user_group_arns, get_user_credentials
# Import getter/setter module for AWS Config
import config
from config import config
# Import getter/setter module for AWS resources & tags
import resources_tags
from resources_tags import resources_tags
# Import getter/setter module for AWS IAM
import iam
from iam import roles
# Import getter module for TagOption Groups
import get_tag_groups
from get_tag_groups import get_tag_groups
# Import setter module for TagOption Groups
import set_tag_groups
from set_tag_groups import set_tag_group
# Import getter/setter module for AWS Service Catalog
import service_catalog
from service_catalog import service_catalog
# Import getter/setter module for AWS SSM Parameter Store
import ssm_parameter_store
from ssm_parameter_store import ssm_parameter_store
# Import AWS STS functions
#from sts import get_session_credentials
# Import Tag Tamer utility functions
from utilities import get_resource_type_unit, verify_jwt

# Import flask framework module & classes to build API's
import flask, flask_wtf
from flask import Flask, flash, jsonify, make_response, redirect, render_template, request, url_for
# Use only flask_awscognito version 1.2.8 or higher from Tag Tamer
from flask_awscognito import AWSCognitoAuthentication
#from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from flask_wtf.csrf import CSRFProtect
# Import JSON parser
import json
# Import logging module
import logging
# Import Regex
import re
#import OS module
import os
#import systems library
import sys
#import epoch time method
from time import time

# Read in Tag Tamer solution parameters
tag_tamer_parameters_file = open('tag_tamer_parameters.json', "rt")
tag_tamer_parameters = json.load(tag_tamer_parameters_file)

# logLevel options are DEBUG, INFO, WARNING, ERROR or CRITICAL
# Set logLevel in tag_tamer_parameters.json parameters file
if  re.search("DEBUG|INFO|WARNING|ERROR|CRITICAL", tag_tamer_parameters['parameters']['logging_level'].upper()):
    logLevel = tag_tamer_parameters['parameters']['logging_level'].upper()
else:
    logLevel = 'INFO'
logging.basicConfig(filename=tag_tamer_parameters['parameters']['log_file_location'],format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',datefmt='%m/%d/%Y %I:%M:%S %p')
# Set the base/root logging level for tag_tamer.py & all imported modules
logging.getLogger().setLevel(logLevel)
log = logging.getLogger('tag_tamer_main')
# Raise logging level for flask_wtf.csrf
logging.getLogger('flask_wtf.csrf').setLevel('WARNING')
# Raise logging level for WSGI tool kit "werkzeug" that's German for "tool"
logging.getLogger('werkzeug').setLevel('ERROR')

# Get user-specified AWS regions
selected_region = tag_tamer_parameters['parameters']['selected_region']
region = selected_region
log.debug('The selected AWS region is: \"%s\"', region)

# Get AWS Service parameters from AWS SSM Parameter Store
ssm_ps = ssm_parameter_store(region)
# Fully qualified list of SSM Parameter names
ssm_parameter_full_names = ssm_ps.form_parameter_hierarchies(tag_tamer_parameters['parameters']['ssm_parameter_path'], tag_tamer_parameters['parameters']['ssm_parameter_names']) 
log.debug('The full names are: %s', ssm_parameter_full_names)
# SSM Parameters names & values
#ssm_parameters = ssm_ps.ssm_get_parameter_details(ssm_parameter_full_names)
ssm_parameters = ssm_ps.ssm_get_parameter_details(tag_tamer_parameters['parameters']['ssm_parameter_path'])

# Instantiate flask API applications
app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config['AWS_DEFAULT_REGION'] = ssm_parameters['cognito-default-region-value']
app.config['AWS_COGNITO_DOMAIN'] = ssm_parameters['cognito-domain-value']
app.config['AWS_COGNITO_USER_POOL_ID'] = ssm_parameters['cognito-user-pool-id-value']
app.config['AWS_COGNITO_USER_POOL_CLIENT_ID'] = ssm_parameters['cognito-app-client-id']
app.config['AWS_COGNITO_USER_POOL_CLIENT_SECRET'] = ssm_parameters['cognito-app-client-secret-value']
app.config['AWS_COGNITO_REDIRECT_URL'] = ssm_parameters['cognito-redirect-url-value']
app.config['JWT_TOKEN_LOCATION'] = ssm_parameters['jwt-token-location']
app.config['JWT_ACCESS_COOKIE_NAME'] = ssm_parameters['jwt-access-cookie-name']
app.config['JWT_COOKIE_SECURE'] = ssm_parameters['jwt-cookie-secure']
app.config['JWT_COOKIE_CSRF_PROTECT'] = ssm_parameters['jwt-cookie-csrf-protect']

csrf = CSRFProtect(app)
csrf.init_app(app)

aws_auth = AWSCognitoAuthentication(app)
#jwt = JWTManager(app)


# Get the user's session credentials based on username passed in JWT
def get_user_session_credentials(cognito_id_token):
    user_session_credentials = get_user_credentials(cognito_id_token,
        ssm_parameters['cognito-user-pool-id-value'],
        ssm_parameters['cognito-identity-pool-id-value'],
        ssm_parameters['cognito-default-region-value'])
    return user_session_credentials

# Verify user's email & source IP address
def get_user_email_ip(route):
    access_token = False
    id_token = False
    access_token = request.cookies.get('access_token')
    id_token = request.cookies.get('id_token')
    
    if access_token and id_token:
        id_token_claims = dict()
        id_token_claims = verify_jwt(ssm_parameters['cognito-default-region-value'],
            ssm_parameters['cognito-user-pool-id-value'],
            ssm_parameters['cognito-app-client-id'],
            'id_token', id_token)
        if id_token_claims.get('email'):
            user_email = id_token_claims.get('email')
        else:
            user_email = False
    else:
        user_email = False

    if request.headers.get('X-Forwarded-For'):
        source = request.headers.get('X-Forwarded-For')
    elif request.remote_addr:
        source = request.remote_addr
    else:
        source = False
    
    return user_email, source


# Allow users to sign into Tag Tamer via an Amazon Cognito User Pool
@app.route('/log-in')
@app.route('/sign-in')
def sign_in():
    return redirect(aws_auth.get_sign_in_url())

# Redirect the user to the Tag Tamer home page after successful AWS Cognito login
@app.route('/aws_cognito_redirect', methods=['GET'])
def aws_cognito_redirect():
    access_token = False
    id_token = False
    access_token, id_token = aws_auth.get_tokens(request.args)
    if access_token and id_token:  
        response = make_response(render_template('redirect.html'))
        log.debug('function: {} - Received the request arguments'.format(sys._getframe().f_code.co_name))
        response.set_cookie('access_token', value=access_token, secure=True, httponly=True, samesite='Lax')
        response.set_cookie('id_token', value=id_token, secure=True, httponly=True, samesite='Lax')
        return response, 200
    else:
        return redirect(url_for('sign_in'))

# Get response delivers Tag Tamer home page
@app.route('/index.html', methods=['GET'])
@app.route('/index.htm', methods=['GET'])
@app.route('/index', methods=['GET'])
@app.route('/', methods=['GET'])
@aws_auth.authentication_required
def index():
    claims = aws_auth.claims

    user_email, user_source = get_user_email_ip(request)
    
    # Get the user's assigned Cognito user pool group
    cognito_user_group_arn = get_user_group_arns(claims.get('username'), 
        ssm_parameters['cognito-user-pool-id-value'],
        ssm_parameters['cognito-default-region-value'])
    # Grant access if session time not expired & user assigned to Cognito user pool group
    if time() < claims.get('exp') and user_email and user_source and cognito_user_group_arn:
        log.info("Successful login.  User \"{}\" with email: \"{}\" signed in on {} from location: \"{}\"".format(claims.get('username'), user_email, date_time_now(), user_source))
        return render_template('index.html', user_name=claims.get('username'))
    else:
        log.info("Failed login attempt.  User \"{}\" with email: \"{}\" attempted to sign in on {} from location: \"{}\"".format(claims.get('username'), user_email, date_time_now(), user_source))
        return redirect('/sign-in')

# Get response delivers Tag Tamer actions page showing user choices as clickable buttons
@app.route('/actions', methods=['GET'])
@aws_auth.authentication_required
def actions():
    return render_template('actions.html')    

# Get response delivers HTML UI to select AWS resource types that Tag Tamer will find
# Post action initiates tag finding for user selected AWS resource types
@app.route('/find-tags', methods=['GET'])
@aws_auth.authentication_required
def find_tags():
    user_email, user_source = get_user_email_ip(request)
    if user_email:
        log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source))
        return render_template('find-tags.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Pass Get response to found-tags HTML UI
@app.route('/found-tags', methods=['POST'])
@aws_auth.authentication_required
def found_tags():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        resource_type, unit = get_resource_type_unit(request.form.get('resource_type'))
        log.debug('function: {} - Received the request arguments'.format(sys._getframe().f_code.co_name))
        inventory = resources_tags(resource_type, unit, region)
        sorted_tagged_inventory, execution_status = inventory.get_resources_tags(**session_credentials)
        flash(execution_status['status_message'], execution_status['alert_level'])
        if execution_status.get('alert_level') == 'success':
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            return render_template('found-tags.html', inventory=sorted_tagged_inventory)
        elif execution_status.get('alert_level') == 'warning':
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            return render_template('blank.html')
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('You are not authorized to view these resources', 'danger')
            return render_template('blank.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Delivers HTML UI to select AWS resource types to manage Tag Groups for
@app.route('/type-to-tag-group', methods=['GET'])
@aws_auth.authentication_required
def type_to_tag_group():
    user_email, user_source = get_user_email_ip(request)
    if user_email:
        log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source))
        return render_template('type-to-tag-group.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Post response to get tag groups attributes UI
@app.route('/get-tag-group-names', methods=['POST'])
@aws_auth.authentication_required
def get_tag_group_names():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        all_tag_groups = get_tag_groups(region, **session_credentials)
        tag_group_names, execution_status = all_tag_groups.get_tag_group_names()
        flash(execution_status['status_message'], execution_status['alert_level'])
        if execution_status.get('alert_level') == 'success':
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            resource_type, _ = get_resource_type_unit(request.form.get('resource_type'))
            return render_template('display-tag-groups.html',
                inventory=tag_group_names, resource_type=resource_type)
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('You are not authorized to view these resources', 'danger')
            return render_template('blank.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Post method to display edit UI for chosen tag group
@app.route('/edit-tag-group', methods=['POST'])
@aws_auth.authentication_required
def edit_tag_group():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        resource_type, unit = get_resource_type_unit(request.form.get('resource_type'))
        inventory = resources_tags(resource_type, unit, region)
        sorted_tag_values_inventory, execution_status = inventory.get_tag_values(**session_credentials) 
        if execution_status.get('alert_level') == 'success':
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            # If user does not select an existing Tag Group or enter 
            # a new Tag Group name reload this route until valid user input given
            if request.form.get('tag_group_name'):    
                selected_tag_group_name = request.form.get('tag_group_name')
                tag_group = get_tag_groups(region, **session_credentials)
                tag_group_key_values, execution_status = tag_group.get_tag_group_key_values(selected_tag_group_name)
                if execution_status.get('alert_level') == 'success':
                    return render_template('edit-tag-group.html', resource_type=resource_type, selected_tag_group_name=selected_tag_group_name, selected_tag_group_attributes=tag_group_key_values, selected_resource_type_tag_values_inventory=sorted_tag_values_inventory)
                else:
                    flash(execution_status['status_message'], execution_status['alert_level'])
                    return render_template('blank.html')
            elif request.form.get('new_tag_group_name') and re.search("^\w[\w\- ]{0,125}\w$", request.form.get('new_tag_group_name')):
                selected_tag_group_name = request.form.get('new_tag_group_name')
                tag_group_key_values = {}
                return render_template('edit-tag-group.html', resource_type=resource_type, selected_tag_group_name=selected_tag_group_name, selected_tag_group_attributes=tag_group_key_values, selected_resource_type_tag_values_inventory=sorted_tag_values_inventory)
            else:
                return render_template('type-to-tag-group.html')
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash(execution_status['status_message'], execution_status['alert_level'])
            return render_template('blank.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Post method to add or update a tag group
@app.route('/add-update-tag-group', methods=['POST'])
@aws_auth.authentication_required
def add_update_tag_group():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        if request.form.get('new_tag_group_name') and \
            re.search("^\w[\w\- ]{0,125}\w$", request.form.get('new_tag_group_name')) and \
            request.form.get('new_tag_group_key_name') and \
            re.search("^\w[\w\- ]{0,125}\w$", request.form.get('new_tag_group_key_name')):
            tag_group_name = request.form.get('new_tag_group_name')
            tag_group_key_name = request.form.get('new_tag_group_key_name')
            tag_group_action = "create"
        elif request.form.get('selected_tag_group_name') and \
            re.search("^\w[\w\- ]{0,125}\w$", request.form.get('selected_tag_group_name')) and \
            request.form.get('selected_tag_group_key_name') and \
            re.search("^\w[\w\- ]{0,125}\w$", request.form.get('selected_tag_group_key_name')):
            tag_group_name = request.form.get('selected_tag_group_name')
            tag_group_key_name = request.form.get('selected_tag_group_key_name')
            tag_group_action = "update"
        else:
            return render_template('type-to-tag-group.html')

        tag_group_value_options = []
        form_contents = request.form.to_dict()
        for key, value in form_contents.items():
            if value == "checked" and re.search("^\w[\w\- ]{0,223}\w$", key):
                tag_group_value_options.append(key)
        if request.form.get("new_tag_group_values"):
            approved_new_tag_group_values = list()
            new_tag_group_values = request.form.get("new_tag_group_values").split(",")
            for value in new_tag_group_values:
                core_value = value.strip(" ")
                if re.search("^\w[\w\- ]{0,223}\w$", core_value):
                    approved_new_tag_group_values.append(core_value)
            tag_group_value_options.extend(approved_new_tag_group_values)

        tag_group = set_tag_group(region, **session_credentials)
        if tag_group_action == "create":
            execution_status = tag_group.create_tag_group(tag_group_name, tag_group_key_name, tag_group_value_options)
        else:
            execution_status = tag_group.update_tag_group(tag_group_name, tag_group_key_name, tag_group_value_options)
        if execution_status.get('alert_level') == 'success':
            tag_groups = get_tag_groups(region, **session_credentials)
            tag_group_key_values, execution_status = tag_groups.get_tag_group_key_values(tag_group_name)
            if execution_status.get('alert_level') == 'success':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                resource_type, unit = get_resource_type_unit(request.form.get('resource_type'))
                inventory = resources_tags(resource_type, unit, region)
                sorted_tag_values_inventory, sorted_tag_values_execution_status = inventory.get_tag_values(**session_credentials)
                return render_template('edit-tag-group.html', resource_type=resource_type, selected_tag_group_name=tag_group_name, selected_tag_group_attributes=tag_group_key_values, selected_resource_type_tag_values_inventory=sorted_tag_values_inventory)
            else:
                log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash(execution_status['status_message'], execution_status['alert_level'])
                return render_template('blank.html')
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash(execution_status['status_message'], execution_status['alert_level'])
            return render_template('blank.html')

# Delivers HTML UI to select AWS resource type to tag using Tag Groups
@app.route('/select-resource-type', methods=['POST'])
@aws_auth.authentication_required
def select_resource_type():
    user_email, user_source = get_user_email_ip(request)
    if user_email:
        log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source))
        next_route  = request.form.get('next_route')
        if not next_route:
            next_route = 'tag_filter'
        return render_template('select-resource-type.html', destination_route=next_route)
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html') 

# Let user search existing tags then tag matching, existing resources 
@app.route('/tag-filter', methods=['POST'])
@aws_auth.authentication_required
def tag_filter():
    user_email, user_source = get_user_email_ip(request)
    if user_email:
        log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source)) 
        if request.form.get('resource_type'):
            return render_template('search-tag-resources-container.html', resource_type=request.form.get('resource_type')) 
        else:
            return render_template('select-resource-type.html', destination_route='tag_filter')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Enter existing tag keys & values to search 
@app.route('/tag-based-search', methods=['GET'])
@aws_auth.authentication_required
def tag_based_search():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        if request.args.get('resource_type'):
            resource_type, unit = get_resource_type_unit(request.args.get('resource_type'))
            inventory = resources_tags(resource_type, unit, region)
            selected_tag_keys, execution_status_tag_keys = inventory.get_tag_keys(**session_credentials)
            selected_tag_values, execution_status_tag_values = inventory.get_tag_values(**session_credentials)
            if execution_status_tag_keys.get('alert_level') == 'success' and execution_status_tag_values.get('alert_level') == 'success':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                return render_template('tag-search.html', 
                        resource_type=request.args.get('resource_type'),
                        tag_keys=selected_tag_keys, 
                        tag_values=selected_tag_values)
            elif execution_status_tag_keys.get('alert_level') == 'warning' or execution_status_tag_values.get('alert_level') == 'warning':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash(execution_status_tag_keys['status_message'], execution_status_tag_keys['alert_level'])
                return render_template('blank.html')
            else:
                log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash(execution_status_tag_keys['status_message'], execution_status_tag_keys['alert_level'])
                return render_template('blank.html')
        else:
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            return render_template('select-resource-type.html', destination_route='tag_filter')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Delivers HTML UI to assign tags from Tag Groups to chosen AWS resources
@app.route('/tag_resources', methods=['GET','POST'])
@aws_auth.authentication_required
def tag_resources():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        if request.form.get('resource_type'):
            filter_elements = dict()
            if request.form.get('tag_key1'):
                filter_elements['tag_key1'] = request.form.get('tag_key1')
            if request.form.get('tag_value1'):
                filter_elements['tag_value1'] = request.form.get('tag_value1')
            if request.form.get('tag_key2'):
                filter_elements['tag_key2'] = request.form.get('tag_key2')
            if request.form.get('tag_value2'):
                filter_elements['tag_value2'] = request.form.get('tag_value2')
            if request.form.get('conjunction'):
                filter_elements['conjunction'] = request.form.get('conjunction')
            
            resource_type, unit = get_resource_type_unit(request.form.get('resource_type'))
            chosen_resource_inventory = resources_tags(resource_type, unit, region)
            chosen_resources = OrderedDict()
            chosen_resources, resources_execution_status = chosen_resource_inventory.get_resources(filter_elements, **session_credentials)
            
            tag_group_inventory = get_tag_groups(region, **session_credentials)
            tag_groups_all_info, tag_groups_execution_status = tag_group_inventory.get_all_tag_groups_key_values(region, **session_credentials)
            if resources_execution_status.get('alert_level') == 'success' and tag_groups_execution_status.get('alert_level') == 'success':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                return render_template('tag-resources.html', resource_type=resource_type, resource_inventory=chosen_resources, tag_groups_all_info=tag_groups_all_info) 
            else:
                log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash('You are not authorized to modify these resources', 'danger')
                return render_template('blank.html')
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            return render_template('blank.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Delivers HTML UI to assign tags from Tag Groups to chosen AWS resources
@app.route('/apply-tags-to-resources', methods=['POST'])
@aws_auth.authentication_required
def apply_tags_to_resources():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        if request.form.getlist('resources_to_tag'):
            resources_to_tag = []
            resources_to_tag = request.form.getlist('resources_to_tag')
            
            form_contents = request.form.to_dict()
            form_contents.pop("resources_to_tag")
        
            resource_type, unit = get_resource_type_unit(request.form.get('resource_type'))
            chosen_resources_to_tag = resources_tags(resource_type, unit, region) 
            form_contents.pop("resource_type")
            form_contents.pop("csrf_token")

            chosen_tags = list()
            for key, value in form_contents.items():
                if value:
                    tag_kv = dict()
                    tag_kv["Key"] = key
                    tag_kv["Value"] = value
                    chosen_tags.append(tag_kv)
            execution_status = chosen_resources_to_tag.set_resources_tags(resources_to_tag, chosen_tags, **session_credentials)
            flash(execution_status['status_message'], execution_status['alert_level'])
            if execution_status.get('alert_level') == 'success':
                updated_sorted_tagged_inventory = dict()
                all_sorted_tagged_inventory, all_sorted_tagged_inventory_execution_status = chosen_resources_to_tag.get_resources_tags(**session_credentials)
                for resource_id in resources_to_tag:
                    updated_sorted_tagged_inventory[resource_id] = all_sorted_tagged_inventory[resource_id]   
                return render_template('updated-tags.html', inventory=updated_sorted_tagged_inventory)
            else:
                log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash('You are not authorized to view these resources', 'danger')
                return render_template('blank.html')
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('You are not authorized to view these resources', 'danger')
            return render_template('blank.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Retrieves AWS Service Catalog products & Tag Groups
@app.route('/get-service-catalog', methods=['GET'])
@aws_auth.authentication_required
def get_service_catalog():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        #Get the Tag Group names & associated tag keys
        tag_group_inventory = dict()
        tag_groups = get_tag_groups(region, **session_credentials)
        tag_group_inventory, tag_groups_execution_status = tag_groups.get_tag_group_names()

        #Get the Service Catalog product templates
        sc_product_ids_names = dict()
        sc_products = service_catalog(region, **session_credentials)
        sc_product_ids_names, sc_product_ids_names_execution_status = sc_products.get_sc_product_templates()
        
        if sc_product_ids_names_execution_status.get('alert_level') == 'success' and tag_groups_execution_status.get('alert_level') == 'success':
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            return render_template('update-service-catalog.html', tag_group_inventory=tag_group_inventory, sc_product_ids_names=sc_product_ids_names)
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('You are not authorized to modify these resources', 'danger')
            return render_template('blank.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Updates AWS Service Catalog product templates with TagOptions using Tag Groups
@app.route('/set-service-catalog', methods=['POST'])
@aws_auth.authentication_required
def set_service_catalog():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        if request.form.getlist('tag_groups_to_assign') and request.form.getlist('chosen_sc_product_template_ids'):
            selected_tag_groups = list()
            selected_tag_groups = request.form.getlist('tag_groups_to_assign')
            sc_product_templates = list()
            sc_product_templates = request.form.getlist('chosen_sc_product_template_ids')

            #Get the Service Catalog product templates
            sc_product_ids_names = dict()
            sc_products = service_catalog(region, **session_credentials)
            sc_product_ids_names, sc_product_ids_names_execution_status = sc_products.get_sc_product_templates()

            #Assign every tag in selected Tag Groups to selected SC product templates
            updated_product_temp_tagoptions = defaultdict(list)
            sc_response = dict()
            for sc_prod_template_id in sc_product_templates:
                for tag_group_name in selected_tag_groups:
                    sc_response.clear()
                    sc_response, sc_response_execution_status = sc_products.assign_tg_sc_product_template(tag_group_name, sc_prod_template_id, **session_credentials)
                    updated_product_temp_tagoptions[sc_prod_template_id].append(sc_response)
            
            if sc_response_execution_status.get('alert_level') == 'success' and sc_product_ids_names_execution_status.get('alert_level') == 'success':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash('TagOptions update succeeded!', 'success')
                return render_template('updated-service-catalog.html', sc_product_ids_names=sc_product_ids_names, updated_product_temp_tagoptions=updated_product_temp_tagoptions)
            elif sc_response_execution_status.get('alert_level') == 'warning' and sc_product_ids_names_execution_status.get('alert_level') == 'success':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash(sc_response_execution_status['status_message'], sc_response_execution_status['alert_level'])
                return render_template('updated-service-catalog.html', sc_product_ids_names=sc_product_ids_names, updated_product_temp_tagoptions=updated_product_temp_tagoptions)
            # for the case of Boto3 errors & unauthorized users
            else:
                log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash('You are not authorized to modify these resources', 'danger')
                return render_template('blank.html')    
        else:
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('Please select at least one Tag Group and Service Catalog product.', 'warning')
            return redirect(url_for('get_service_catalog'))
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Retrieves AWS Config Rules & Tag Groups
@app.route('/find-config-rules', methods=['GET'])
@aws_auth.authentication_required
def find_config_rules():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        #Get the Tag Group names & associated tag keys
        tag_group_inventory = dict()
        tag_groups = get_tag_groups(region, **session_credentials)
        tag_group_inventory, tag_groups_execution_status = tag_groups.get_tag_group_names()

        #Get the AWS Config Rules
        config_rules_ids_names = dict()
        config_rules = config(region, **session_credentials)
        config_rules_ids_names, config_rules_execution_status = config_rules.get_config_rules_ids_names()
        
        if config_rules_execution_status.get('alert_level') == 'success' and tag_groups_execution_status.get('alert_level') == 'success':
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            return render_template('find-config-rules.html', tag_group_inventory=tag_group_inventory, config_rules_ids_names=config_rules_ids_names)
        elif config_rules_execution_status.get('alert_level') == 'warning' and tag_groups_execution_status.get('alert_level') == 'success':
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash(config_rules_execution_status['status_message'], config_rules_execution_status['alert_level'])
            return render_template('find-config-rules.html', tag_group_inventory=tag_group_inventory, config_rules_ids_names=config_rules_ids_names)
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('You are not authorized to modify these resources', 'danger')
            return render_template('blank.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')
        
# Updates AWS Config's required-tags rule using Tag Groups
@app.route('/update-config-rules', methods=['POST'])
@aws_auth.authentication_required
def set_config_rules():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        if request.form.getlist('tag_groups_to_assign') and request.form.getlist('chosen_config_rule_ids'):
            selected_tag_groups = list()
            selected_tag_groups = request.form.getlist('tag_groups_to_assign')
            selected_config_rules = list()
            selected_config_rules = request.form.getlist('chosen_config_rule_ids')
            config_rule_id = selected_config_rules[0]

            tag_groups = get_tag_groups(region, **session_credentials)
            tag_group_key_values = dict()
            tag_groups_keys_values = dict()
            tag_count=1
            for group in selected_tag_groups:
                # A Required_Tags Config Rule instance accepts up to 6 Tag Groups
                if tag_count < 7:
                    tag_group_key_values, key_values_execution_status = tag_groups.get_tag_group_key_values(group)
                    key_name = "tag{}Key".format(tag_count)
                    value_name = "tag{}Value".format(tag_count)
                    tag_groups_keys_values[key_name] = tag_group_key_values['tag_group_key']
                    tag_group_values_string = ",".join(tag_group_key_values['tag_group_values'])
                    tag_groups_keys_values[value_name] = tag_group_values_string
                    tag_count+=1

            config_rules = config(region, **session_credentials)
            set_rules_execution_status = config_rules.set_config_rules(tag_groups_keys_values, config_rule_id)
            updated_config_rule, get_rule_execution_status = config_rules.get_config_rule(config_rule_id)
            flash(set_rules_execution_status['status_message'], set_rules_execution_status['alert_level'])
            if set_rules_execution_status.get('alert_level') == 'success' and get_rule_execution_status.get('alert_level') == 'success':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                return render_template('updated-config-rules.html', updated_config_rule=updated_config_rule)
            elif set_rules_execution_status.get('alert_level') == 'warning':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                return redirect(url_for('find_config_rules'))
            # for the case of Boto3 errors & unauthorized users
            else:
                log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash('You are not authorized to view these resources', 'danger')
                return render_template('blank.html')
        else:
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('Please select at least one Tag Group and Config rule.', 'warning')
            return redirect(url_for('find_config_rules'))
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Retrieves AWS IAM Roles & Tag Groups
@app.route('/select-roles-tags', methods=['GET'])
@aws_auth.authentication_required
def select_roles_tags():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        tag_group_inventory = get_tag_groups(region, **session_credentials)
        tag_groups_all_info, tag_groups_all_execution_status = tag_group_inventory.get_all_tag_groups_key_values(region, **session_credentials)

        iam_roles = roles(region, **session_credentials)
        # In initial Tag Tamer release get AWS SSO Roles
        path_prefix = "/aws-reserved/sso.amazonaws.com/"
        roles_inventory, roles_execution_status = iam_roles.get_roles(path_prefix)

        # User notifications based on her/his permission to access IAM Roles
        flash(roles_execution_status['status_message'], roles_execution_status['alert_level'])
        if roles_execution_status.get('alert_level') == 'success' and tag_groups_all_execution_status.get('alert_level') == 'success':
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            return render_template('tag-roles.html', roles_inventory=roles_inventory, tag_groups_all_info=tag_groups_all_info)
        # for the case of Boto3 errors & unauthorized users
        else:
            log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('You are not authorized to view these resources', 'danger')
            return render_template('blank.html')
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

# Assigns selected tags to roles for tagging newly created AWS resources
@app.route('/set-roles-tags', methods=['POST'])
@aws_auth.authentication_required
def set_roles_tags():
    user_email, user_source = get_user_email_ip(request)
    session_credentials = get_user_session_credentials(request.cookies.get('id_token'))
    if user_email and session_credentials.get('AccessKeyId'):
        if request.form.get('roles_to_tag'):
            role_name = request.form.get('roles_to_tag')
            form_contents = request.form.to_dict()
            form_contents.pop('roles_to_tag')
            form_contents.pop("csrf_token")

            chosen_tags = list()
            for key, value in form_contents.items():
                if value:
                    tag_kv = {}
                    tag_kv["Key"] = key
                    tag_kv["Value"] = value
                    chosen_tags.append(tag_kv)

            role_to_tag = roles(region, **session_credentials)
            execution_status = role_to_tag.set_role_tags(role_name, chosen_tags)
            flash(execution_status['status_message'], execution_status['alert_level'])
            if execution_status.get('alert_level') == 'success':
                log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                return redirect(url_for('select_roles_tags'))
            # for the case of Boto3 errors & unauthorized users
            else:
                log.error("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - FAILURE".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
                flash('You are not authorized to view these resources', 'danger')
                return render_template('blank.html')
        else:
            log.info("\"{}\" invoked \"{}\" on {} from location: \"{}\" using AWSAuth access key id: {} - SUCCESS".format(user_email, sys._getframe().f_code.co_name, date_time_now(), user_source, session_credentials['AccessKeyId']))
            flash('Please select at least one Tag Group and IAM SSO Role.', 'warning')
            return redirect(url_for('select_roles_tags'))
    else:
        log.error("Unknown user attempted to invoke \"{}\" on {} from location: \"{}\" - FAILURE".format(sys._getframe().f_code.co_name, date_time_now(), user_source))
        flash('You are not authorized to view these resources', 'danger')
        return render_template('blank.html')

@app.route('/logout', methods=['GET'])
@aws_auth.authentication_required
def logout():
    claims = aws_auth.claims
    user_email, user_source = get_user_email_ip(request)
    log.info("Successful logout.  User \"{}\" with email \"{}\" signed out on {} from location \"{}\"".format(claims.get('username'), user_email, date_time_now(), user_source))
    response = make_response(render_template('logout.html'))
    response.delete_cookie('access_token')
    response.delete_cookie('id_token')
    response.delete_cookie('session')
    return response, 200       
