"""
The following playbook allows for recon on any Hash artifact. This includes MD5, SHA1, SHA256, and SHA512
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHashMd5", ">=", "1"],
            ["artifact:*.cef.fileHashSha1", ">=", "1"],
            ["artifact:*.cef.fileHashSha256", ">=", "1"],
            ["artifact:*.cef.fileHashSha512", ">=", "1"],
        ],
        logical_operator='or',
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_SHA1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        file_reputation_MD5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        file_reputation_SHA256(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        file_reputation_SHA512(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def file_reputation_SHA1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_SHA1() called')

    # collect data for 'file_reputation_SHA1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHashSha1', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_SHA1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal_api'], callback=join_filter_2, name="file_reputation_SHA1")

    return

def file_reputation_MD5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_MD5() called')

    # collect data for 'file_reputation_MD5' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashMd5', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_MD5' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal_api'], callback=join_filter_2, name="file_reputation_MD5")

    return

def file_reputation_SHA256(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_SHA256() called')

    # collect data for 'file_reputation_SHA256' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHashSha256', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_SHA256' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal_api'], callback=join_filter_2, name="file_reputation_SHA256")

    return

def file_reputation_SHA512(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_SHA512() called')

    # collect data for 'file_reputation_SHA512' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHashSha512', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_SHA512' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal_api'], callback=join_filter_2, name="file_reputation_SHA512")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_SHA1:action_result.data.*.response_code", "==", 0],
            ["file_reputation_MD5:action_result.data.*.resource", "==", 0],
            ["file_reputation_SHA256:action_result.data.*.response_code", "==", 0],
            ["file_reputation_SHA512:action_result.data.*.response_code", "==", 0],
        ],
        logical_operator='or',
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_SHA1:action_result.data.*.positives", ">=", "5"],
            ["file_reputation_MD5:action_result.data.*.positives", ">=", "5"],
            ["file_reputation_SHA256:action_result.data.*.positives", ">=", "5"],
            ["file_reputation_SHA512:action_result.data.*.positives", ">=", "5"],
        ],
        logical_operator='or',
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def join_filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_filter_2() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'file_reputation_SHA1', 'file_reputation_MD5', 'file_reputation_SHA256', 'file_reputation_SHA512' ]):
        
        # call connected block "filter_2"
        filter_2(container=container, handle=handle)
    
    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The following Hash is malicious
{1}{0}{3}{2}
{4}{6}{5}{7}
Do you want to block this Hash?"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.fileHashSha1",
        "artifact:*.cef.fileHashMd5",
        "artifact:*.cef.fileHashSha256",
        "artifact:*.cef.fileHashSha512",
        "file_reputation_SHA1:action_result.data.*.positives",
        "file_reputation_MD5:action_result.data.*.positives",
        "file_reputation_SHA256:action_result.data.*.positives",
        "file_reputation_SHA512:action_result.data.*.positives",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types)

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