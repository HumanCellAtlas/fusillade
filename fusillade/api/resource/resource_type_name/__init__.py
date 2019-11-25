from flask import request, make_response, jsonify

from fusillade.directory.resource import ResourceType
from fusillade.utils.authorize import authorize


@authorize(["fus:GetResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}"],
           resource_params=['resource_type_name'])
def get(token_info: dict, resource_type_name):
    rt = ResourceType(resource_type_name)
    rt._exists([rt.name])
    info = rt.get_info()
    return make_response(info, 200)


@authorize(["fus:PostResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}"],
           resource_params=['resource_type_name'])
def post(token_info: dict, resource_type_name):
    json_body = request.json
    rt = ResourceType.create(resource_type_name, json_body['actions'])
    return make_response(f"New resource type {rt.name} created.", 201)


@authorize(["fus:DeleteResources"],
           ["arn:hca:fus:*:*:resource/{resource_type_name}"],
           resource_params=['resource_type_name'])
def delete(token_info: dict, resource_type_name):
    rt = ResourceType(resource_type_name)
    rids = rt.list_ids()[0]
    if rids:
        # TODO write tests for this once create resource_id API is complete
        return make_response(jsonify(
            {'msg': 'All resource ids must be deleted before the resource type can be deleted.',
             'resource_ids': rids}), 409)
    rt.delete_node()
    return make_response(jsonify({
        'msg': "Resource type deleted.",
        'resource_type': rt.name}),
        200
    )
