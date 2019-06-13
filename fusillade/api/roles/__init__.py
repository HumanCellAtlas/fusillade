from flask import request, make_response, jsonify

from fusillade import Role
from fusillade.api.paging import get_next_token, get_page
from fusillade.utils.authorize import authorize


@authorize(['fus:PostRole'], ['arn:hca:fus:*:*:role'])
def post_role(token_info: dict):
    json_body = request.json
    Role.create(json_body['role_id'], statement=json_body.get('policy'),
                creator=token_info['https://auth.data.humancellatlas.org/email'])
    return make_response(f"New role {json_body['role_id']} created.", 201)


@authorize(['fus:GetRole'], ['arn:hca:fus:*:*:role'])
def get_roles(token_info: dict):
    next_token, per_page = get_next_token(request.args)
    return get_page(Role.list_all, next_token, per_page)


@authorize(['fus:GetRole'], ['arn:hca:fus:*:*:role/{role_id}/'], ['role_id'])
def get_role(token_info: dict, role_id: str):
    role = Role(role_id)
    return make_response(jsonify(role.get_info()), 200)


@authorize(['fus:PutRole'], ['arn:hca:fus:*:*:role/{role_id}/'], ['role_id'])
def put_role_policy(token_info: dict, role_id: str):
    role = Role(role_id)
    role.set_policy(request.json['policy'])
    return make_response('Role policy updated.', 200)
