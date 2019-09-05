"""
This playbook will take the following data and run through recon modules:

new stuff

Actions include:

Phantom DNS
Phantom IP
VirusTotal
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

import sys
import urllib 
import urlparse
import time

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_14' block
    filter_14(container=container)

    # call 'filter_16' block
    filter_16(container=container)

    # call 'filter_12' block
    filter_12(container=container)

    # call 'filter_20' block
    filter_20(container=container)

    return

def prompt_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_5() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Exmerge?"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_5", response_types=response_types, callback=filter_9)

    return

def filter_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_9() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_5:action_result.summary.responses.0", "==", "Yes"],
        ],
        name="filter_9:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_17:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_17:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("domain reputation", parameters=parameters, assets=['virustotal_api'], callback=filter_13, name="domain_reputation_1")

    return

def filter_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_12() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", ">=", "1"],
        ],
        name="filter_12:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_SOAR_URL_Recon_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_13() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.data.*.detected_urls.*.positives", ">=", "3"],
        ],
        name="filter_13:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_9(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def prompt_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_9() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """This is a bad domain and needs to be blocked"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_9", response_types=response_types, callback=prompt_5)

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['virustotal_api'], callback=prompt_10, name="ip_reputation_1")

    return

def filter_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_14() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", ">=", "1"],
        ],
        name="filter_14:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def prompt_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_10() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """IP info
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_reputation_1:action_result.data.*.detected_communicating_samples.*.positives",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_10", parameters=parameters, response_types=response_types)

    return

def filter_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_16() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationDnsDomain", ">=", "1"],
        ],
        name="filter_16:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_17(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_17() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["urldefense.proofpoint.com", "not in", "artifact:*.cef.destinationDnsDomain"],
        ],
        name="filter_17:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_20(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_20() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashSha256", ">=", "1"],
            ["artifact:*.cef.fileHashMd5", ">=", "1"],
            ["artifact:*.cef.fileHashSha1", ">=", "1"],
            ["artifact:*.cef.fileHashSha512", ">=", "1"],
        ],
        logical_operator='or',
        name="filter_20:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_SOAR_Hash_Recon_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def playbook_SOAR_URL_Recon_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_SOAR_URL_Recon_1() called')
    
    # call playbook "SOAR/URL_Recon", returns the playbook_run_id
    playbook_run_id = phantom.playbook("SOAR/URL_Recon", container=container, name="playbook_SOAR_URL_Recon_1")

    return

def playbook_SOAR_Hash_Recon_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_SOAR_Hash_Recon_1() called')
    
    # call playbook "SOAR/Hash_Recon", returns the playbook_run_id
    playbook_run_id = phantom.playbook("SOAR/Hash_Recon", container=container, name="playbook_SOAR_Hash_Recon_1")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return