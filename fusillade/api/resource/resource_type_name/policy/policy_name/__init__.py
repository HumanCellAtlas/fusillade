from flask import request, make_response, jsonify

from fusillade.directory.resource import ResourceType
from fusillade.utils.authorize import authorize


@authorize(["fus:GetResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/policy/{policy_name}"],
           resource_params=['resource_type_name', 'policy_name'])
def get(token_info: dict, resource_type_name, policy_name):
    rt = ResourceType(resource_type_name)
    rt._exists([rt.name])
    policy = rt.get_policy(policy_name)
    return make_response(jsonify(policy), 200)


@authorize(["fus:PostResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/policy/{policy_name}"],
           resource_params=['resource_type_name', 'policy_name'])
def post(token_info: dict, resource_type_name, policy_name):
    json_body = request.json
    rt = ResourceType(resource_type_name)
    rt.create_policy(policy_name, json_body['policy'], 'ResourcePolicy')
    return make_response(f"Created resource/{resource_type_name}/policy/{policy_name}.", 201)


@authorize(["fus:PutResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/policy/{policy_name}"],
           resource_params=['resource_type_name', 'policy_name'])
def put(token_info: dict, resource_type_name, policy_name):
    json_body = request.json
    rt = ResourceType(resource_type_name)
    rt.update_policy(policy_name, json_body['policy'], 'ResourcePolicy')
    return make_response(f"Modified resource/{resource_type_name}/policy/{policy_name}.", 201)


@authorize(["fus:DeleteResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/policy/{policy_name}"],
           resource_params=['resource_type_name', 'policy_name'])
def delete(token_info: dict, resource_type_name, policy_name):
    rt = ResourceType(resource_type_name)
    rt.delete_policy(policy_name)
    return make_response(f"Deleted resource/{resource_type_name}/policy/{policy_name}.", 200)
