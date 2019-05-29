from flask import request, make_response, jsonify

from fusillade import Role, directory
from fusillade.utils.authorize import assert_authorized
from fusillade.api.paging import get_next_token, get_page


def put_new_role(token_info: dict):
    assert_authorized(token_info['https://auth.data.humancellatlas.org/email'],
                      ['fus:PutRole'],
                      ['arn:hca:fus:*:*:role'])
    json_body = request.json
    Role.create(directory, json_body['role_id'], statement=json_body.get('policy'))
    return make_response(f"New role {json_body['role_id']} created.", 201)


def get_roles(token_info: dict):
    assert_authorized(token_info['https://auth.data.humancellatlas.org/email'],
                      ['fus:GetRole'],
                      [f'arn:hca:fus:*:*:role'])
    next_token, per_page = get_next_token(request.args)
    return get_page(Role.list_all, next_token, per_page, directory)

def get_role(token_info: dict, role_id: str):
    assert_authorized(token_info['https://auth.data.humancellatlas.org/email'],
                      ['fus:GetRole'],
                      [f'arn:hca:fus:*:*:role/{role_id}'])
    role = Role(directory, role_id)
    resp = dict(
        role_id=role.name,
        policy=role.statement
    )
    return make_response(jsonify(resp), 200)


def put_role_policy(token_info: dict, role_id: str):
    assert_authorized(token_info['https://auth.data.humancellatlas.org/email'],
                      ['fus:PutRole'],
                      [f'arn:hca:fus:*:*:role/{role_id}'])
    role = Role(directory, role_id)
    role.statement = request.json['policy']
    return make_response('Role policy updated.', 200)
