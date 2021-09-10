"""
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: MIT-0

    Tag Tamer utility functions to evaluate resource tags
"""

import logging

# Instantiate logging for this module using its file name
log = logging.getLogger(__name__)


def tag_filter_matcher(
    conjunction=None,
    tag_key1_state=None,
    tag_value1_state=None,
    tag_key2_state=None,
    tag_value2_state=None,
    resource_inventory=None,
    filter_tags=None,
    tag_dict=None,
    resource_name=None,
    resource_arn=None,
):
    """Updates the passed resource_inventory dictionary with ARN & name of all resources matching the
    user-selected filter tag keys & values. User-selected filter tag keys & tag key:value combinations
    are AND'ed or OR'ed based on value of conjunction.
    """

    def _intersection_union_invalid(tag_dict, resource_name, resource_arn):
        resource_inventory.clear()

    def _intersection_union_fftt(tag_dict, resource_name, resource_arn):
        if tag_dict.get(filter_tags.get("tag_key2")) == filter_tags.get("tag_value2"):
            resource_inventory[resource_arn] = resource_name

    def _intersection_union_ttff(tag_dict, resource_name, resource_arn):
        if tag_dict.get(filter_tags.get("tag_key1")) == filter_tags.get("tag_value1"):
            resource_inventory[resource_arn] = resource_name

    def _intersection_tfff(tag_dict, resource_name, resource_arn):
        if filter_tags.get("tag_key1") in tag_dict:
            resource_inventory[resource_arn] = resource_name

    def _intersection_fftf(tag_dict, resource_name, resource_arn):
        if filter_tags.get("tag_key2") in tag_dict:
            resource_inventory[resource_arn] = resource_name

    def _intersection_tftf(tag_dict, resource_name, resource_arn):
        if (
            filter_tags.get("tag_key1") in tag_dict
            and filter_tags.get("tag_key2") in tag_dict
        ):
            resource_inventory[resource_arn] = resource_name

    def _intersection_tftt(tag_dict, resource_name, resource_arn):
        if (
            filter_tags.get("tag_key1") in tag_dict
            and filter_tags.get("tag_key2") in tag_dict
        ):
            if tag_dict.get(filter_tags.get("tag_key2")) == filter_tags.get(
                "tag_value2"
            ):
                resource_inventory[resource_arn] = resource_name

    def _intersection_tttf(tag_dict, resource_name, resource_arn):
        if (
            filter_tags.get("tag_key1") in tag_dict
            and filter_tags.get("tag_key2") in tag_dict
        ):
            if tag_dict.get(filter_tags.get("tag_key1")) == filter_tags.get(
                "tag_value1"
            ):
                resource_inventory[resource_arn] = resource_name

    def _intersection_tttt(tag_dict, resource_name, resource_arn):
        if tag_dict.get(filter_tags.get("tag_key1")) == filter_tags.get(
            "tag_value1"
        ) and tag_dict.get(filter_tags.get("tag_key2")) == filter_tags.get(
            "tag_value2"
        ):
            resource_inventory[resource_arn] = resource_name

    def _intersection_ffff(tag_dict, resource_name, resource_arn):
        resource_inventory[resource_arn] = resource_name

    def _union_tfff_tftf_fftf(tag_dict, resource_name, resource_arn):
        if (
            filter_tags.get("tag_key1") in tag_dict
            or filter_tags.get("tag_key2") in tag_dict
        ):
            resource_inventory[resource_arn] = resource_name

    def _union_tttf(tag_dict, resource_name, resource_arn):
        if filter_tags.get("tag_key1") in tag_dict:
            if tag_dict[filter_tags.get("tag_key1")] == filter_tags.get("tag_value1"):
                resource_inventory[resource_arn] = resource_name
        elif filter_tags.get("tag_key2") in tag_dict:
            resource_inventory[resource_arn] = resource_name

    def _union_tftt(tag_dict, resource_name, resource_arn):
        if filter_tags.get("tag_key2") in tag_dict:
            if tag_dict[filter_tags.get("tag_key2")] == filter_tags.get("tag_value2"):
                resource_inventory[resource_arn] = resource_name
        elif filter_tags.get("tag_key1") in tag_dict:
            resource_inventory[resource_arn] = resource_name

    def _union_tttt(tag_dict, resource_name, resource_arn):
        if tag_dict.get(filter_tags.get("tag_key1")) == filter_tags.get(
            "tag_value1"
        ) or tag_dict.get(filter_tags.get("tag_key2")) == filter_tags.get("tag_value2"):
            resource_inventory[resource_arn] = resource_name

    def _union_ffff(tag_dict, resource_name, resource_arn):
        resource_inventory[resource_arn] = resource_name

    # "AND" Truth table check for tag_key1, tag_value1, tag_key2, tag_value2
    intersection_combos = {
        (False, False, False, True): _intersection_union_invalid,
        (False, True, False, False): _intersection_union_invalid,
        (False, True, False, True): _intersection_union_invalid,
        (True, False, False, True): _intersection_union_invalid,
        (True, True, False, True): _intersection_union_invalid,
        (False, True, True, False): _intersection_union_invalid,
        (False, False, True, False): _intersection_fftf,
        (False, False, True, True): _intersection_union_fftt,
        (True, False, False, False): _intersection_tfff,
        (True, True, False, False): _intersection_union_ttff,
        (True, False, True, False): _intersection_tftf,
        (True, False, True, True): _intersection_tftt,
        (True, True, True, False): _intersection_tttf,
        (True, True, True, True): _intersection_tttt,
        (False, False, False, False): _intersection_ffff,
    }

    # "OR" Truth table check for tag_key1, tag_value1, tag_key2, tag_value2
    union_combos = {
        (False, False, False, True): _intersection_union_invalid,
        (False, True, False, False): _intersection_union_invalid,
        (False, True, False, True): _intersection_union_invalid,
        (False, True, True, True): _intersection_union_invalid,
        (True, True, False, True): _intersection_union_invalid,
        (False, False, True, False): _union_tfff_tftf_fftf,
        (False, False, True, True): _intersection_union_fftt,
        (True, False, False, False): _union_tfff_tftf_fftf,
        (True, False, True, False): _union_tfff_tftf_fftf,
        (True, False, True, True): _union_tftt,
        (True, True, False, False): _intersection_union_ttff,
        (True, True, True, False): _union_tttf,
        (True, True, True, True): _union_tttt,
        (False, False, False, False): _union_ffff,
    }

    if conjunction == "AND":
        intersection_combos[
            (
                tag_key1_state,
                tag_value1_state,
                tag_key2_state,
                tag_value2_state,
            )
        ](
            tag_dict,
            resource_name,
            resource_arn,
        )
    elif conjunction == "OR":
        union_combos[
            (
                tag_key1_state,
                tag_value1_state,
                tag_key2_state,
                tag_value2_state,
            )
        ](
            tag_dict,
            resource_name,
            resource_arn,
        )
    else:
        _intersection_union_invalid(tag_dict, resource_name, resource_arn)


def get_tag_filter_key_value_states(filter_tags=None):
    tag_key1_state = True if filter_tags.get("tag_key1") else False
    tag_value1_state = True if filter_tags.get("tag_value1") else False
    tag_key2_state = True if filter_tags.get("tag_key2") else False
    tag_value2_state = True if filter_tags.get("tag_value2") else False
    return tag_key1_state, tag_value1_state, tag_key2_state, tag_value2_state
