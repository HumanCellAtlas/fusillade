from flask import make_response, jsonify

from fusillade.directory.resource import ResourceType, ResourceId
from fusillade.utils.authorize import authorize


@authorize(["fus:GetResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/{resource_id}"],
           resource_params=['resource_type_name', 'resource_id'])
def get(token_info: dict, resource_type_name, resource_id):
    rid = ResourceId(resource_type_name, resource_id)
    info = rid.get_info()
    return make_response(info, 200)


@authorize(["fus:PostResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/{resource_id}"],
           resource_params=['resource_type_name', 'resource_id'])
def post(token_info: dict, resource_type_name, resource_id):
    rt = ResourceType(resource_type_name)
    rt.create_id(resource_id)
    return make_response(jsonify({
        'msg': f"Created resource/{rt.name}/id/{resource_id}.",
        'resource_type': rt.name,
        'resource_id': resource_id}), 201)


@authorize(["fus:DeleteResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/{resource_id}"],
           resource_params=['resource_type_name', 'resource_id'])
def delete(token_info: dict, resource_type_name, resource_id):
    rid = ResourceId(resource_type_name, name=resource_id)
    rid.delete_node()
    return make_response(jsonify({
        'msg': f"Deleted resource/{rid.resource_type}/id/{resource_id}.",
        'resource_type': rid.resource_type.name,
        'resource_id': rid.name}), 200)
