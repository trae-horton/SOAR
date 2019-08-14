"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

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

    phantom.act("file reputation", parameters=parameters, assets=['virustotal_api'], callback=decision_1, name="file_reputation_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        create_ticket_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    prompt_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def prompt_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_2() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """This file is clean"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_2", response_types=response_types)

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_ticket_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.data.*.scans.AegisLab.result, file_reputation_1:action_result.data.*.scans.AVG.result', 'file_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    for results_item_1 in results_data_1:
        parameters.append({
            'project_key': "ITSEC",
            'summary': "Test ticket from Phantom",
            'description': results_item_1[0],
            'issue_type': "Task",
            'priority': "",
            'assignee': "",
            'fields': "",
            'vault_id': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act("create ticket", parameters=parameters, assets=['atlassian_api'], name="create_ticket_1")

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