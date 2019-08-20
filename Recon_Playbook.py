"""
This playbook will take the following data and run through recon modules:

Destination IP
Destination DNS
SHA256 Hash


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

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    # call 'Parse_Proofpoint_URL' block
    Parse_Proofpoint_URL(container=container)

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashSha256', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal_api'], callback=File_Filter, name="file_reputation_1")

    return

def detonate_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('detonate_file_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_2' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:artifact:*.cef.cs6', 'file_reputation_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'detonate_file_2' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'vault_id': inputs_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("detonate file", parameters=parameters, assets=['virustotal_api'], callback=filter_8, name="detonate_file_2")

    return

def File_Filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('File_Filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.response_code", "==", 0],
        ],
        name="File_Filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        detonate_file_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", ">=", "5"],
        ],
        name="File_Filter:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        prompt_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def prompt_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_3() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Block Hash?
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_1:action_result.data.*.positives",
    ]

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_3", parameters=parameters, response_types=response_types, callback=join_prompt_5)

    return

def prompt_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_4() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Detonated
Block Hash?
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "detonate_file_2:action_result.data.*.positives",
    ]

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_4", parameters=parameters, response_types=response_types, callback=join_prompt_5)

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_2:action_result.data.*.positives", ">=", "5"],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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

def join_prompt_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_prompt_5() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'prompt_4', 'prompt_3', 'prompt_6', 'prompt_7' ]):
        
        # call connected block "prompt_5"
        prompt_5(container=container, handle=handle)
    
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

def url_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_2() called')
    url_value = container.get('url', None)
    phantom.debu(url_value)
    # collect data for 'url_reputation_2' call

    parameters = []
    
    # build parameters list for 'url_reputation_2' call
    parameters.append({
        'url': url_value,
    })

    phantom.act("url reputation", parameters=parameters, assets=['phishtank'], callback=filter_10, name="url_reputation_2")

    return

def filter_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_10() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_2:action_result.summary.Verified", "==", True],
        ],
        name="filter_10:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_6(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_2:action_result.summary.Verified", "==", False],
        ],
        name="filter_10:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        detonate_url_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def prompt_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_6() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """In PhishTank
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_2:action_result.data.*.positives",
    ]

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_6", parameters=parameters, response_types=response_types, callback=join_prompt_5)

    return

def detonate_url_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('detonate_url_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_url_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonate_url_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("detonate url", parameters=parameters, assets=['virustotal_api'], callback=filter_11, name="detonate_url_2")

    return

def prompt_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_7() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """detinated URL"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_7", response_types=response_types, callback=join_prompt_5)

    return

def filter_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_11() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_url_2:action_result.data.*.positives", ">=", "1"],
        ],
        name="filter_11:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        prompt_7(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Parse_Proofpoint_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Parse_Proofpoint_URL() called')
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])
    container_item_0 = [item[0] for item in container_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug(container_item_0)
    test = container_item_0[0]
        
    query  = urlparse.urlparse(test).query
    param  = urlparse.parse_qs(query)
    u = (param['u'][0].replace('-', '%')
                      .replace('_', '/'))
    url = urllib.unquote(u)

    ################################################################################
    ## Custom Code End
    ################################################################################
    url_reputation_2(container=container)

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