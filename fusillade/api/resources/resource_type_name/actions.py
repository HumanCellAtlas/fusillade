from flask import request, make_response, jsonify

from fusillade.directory.resource import ResourceType
from fusillade.utils.authorize import authorize


@authorize(["fus:GetResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/action"],
           resource_params=['resource_type_name'])
def get(token_info: dict, resource_type_name):
    rt = ResourceType(resource_type_name)
    actions = rt.actions
    return make_response(jsonify({'actions': actions}), 200)


@authorize(["fus:PutResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/action"],
           resource_params=['resource_type_name'])
def put(token_info: dict, resource_type_name):
    json_body = request.json
    rt = ResourceType(resource_type_name)
    rt.add_actions(json_body['actions'])
    return make_response(f"Actions added to resource type {rt.name}.", 200)


@authorize(["fus:DeleteResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/action"],
           resource_params=['resource_type_name'])
def delete(token_info: dict, resource_type_name):
    json_body = request.json
    rt = ResourceType(resource_type_name)
    rt.remove_actions(json_body['actions'])
    return make_response(f"Actions removed from resource type {rt.name}.", 200)
