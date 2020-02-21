from flask import make_response, jsonify, request

from fusillade.api.paging import get_page, get_next_token
from fusillade.directory.resource import ResourceId
from fusillade.utils.authorize import authorize


@authorize(["fus:GetResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/{resource_id}/members"],
           resource_params=['resource_type_name', 'resource_id'])
def get(token_info: dict, resource_type_name, resource_id):
    next_token, per_page = get_next_token(request.args)
    return get_page(
        ResourceId(resource_type_name, resource_id).list_principals,
        next_token,
        per_page,
        content_key='members')


@authorize(["fus:PutResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}/{resource_id}/members"],
           resource_params=['resource_type_name', 'resource_id'])
def put(token_info: dict, resource_type_name, resource_id):
    members = request.json
    rt = ResourceId(resource_type_name, resource_id)
    rt.modify_principals(members)
    return make_response(jsonify({
        'msg': f"Access levels modified.",
        'resource_type': rt.name,
        'resource_id': resource_id}), 200)
