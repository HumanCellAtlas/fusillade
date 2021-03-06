from flask import request, make_response, jsonify

from fusillade import User, Config
from fusillade.api._helper import _modify_roles, _modify_groups
from fusillade.api.paging import get_next_token, get_page
from fusillade.utils.authorize import authorize, get_email_claim


@authorize(['fus:PostUser'], ['arn:hca:fus:*:*:user'])
def post_user(token_info: dict):
    json_body = request.json
    User.provision_user(json_body['user_id'], statement=json_body.get('policy'),
                        creator=get_email_claim(token_info),
                        groups=json_body.get('groups', []),
                        roles=json_body.get('roles', []))
    return make_response(jsonify({'msg': f"{json_body['user_id']} created."}), 201)


@authorize(['fus:GetUser'], ['arn:hca:fus:*:*:user'])
def get_users(token_info: dict):
    next_token, per_page = get_next_token(request.args)
    return get_page(User.list_all, next_token, per_page, 'users')


@authorize(['fus:GetUser'], ['arn:hca:fus:*:*:user/{user_id}/'], ['user_id'])
def get_user(token_info: dict, user_id: str):
    user = User(user_id)
    return make_response(jsonify(user.get_info()), 200)


@authorize(['fus:PutUser'], ['arn:hca:fus:*:*:user/{user_id}/status'], ['user_id'])
def put_user(token_info: dict, user_id: str):
    user = User(user_id)
    new_status = request.args['status']
    resp_json = {'user_id': user_id,
                 'status': new_status,
                 'msg': f"User status set to {new_status}."}
    if new_status == 'enabled':
        user.enable()
        resp = make_response(jsonify(resp_json), 200)
    elif new_status == 'disabled':
        user.disable()
        resp = make_response(jsonify(resp_json), 200)
    else:
        resp = make_response('', 500)
    return resp


@authorize(['fus:GetUser'], ['arn:hca:fus:*:*:user/{user_id}/owns'], ['user_id'])
def get_users_owns(token_info: dict, user_id: str):
    next_token, per_page = get_next_token(request.args)
    user = User(user_id)
    content_key = "roles" if request.args['resource_type'] == "role" else "groups"
    return get_page(user.get_owned,
                    next_token,
                    per_page,
                    content_key,
                    request.args['resource_type'],
                    paged=True)


@authorize(['fus:PutUser'], ['arn:hca:fus:*:*:user/{user_id}/policy'], ['user_id'])
def put_user_policy(token_info: dict, user_id: str):
    user = User(user_id)
    user.set_policy(request.json['policy'])
    return make_response(jsonify({'user_id': user_id,
                                  'msg': "User's policy successfully modified."}), 200)


@authorize(['fus:GetGroup'], ['arn:hca:fus:*:*:user/{user_id}/groups'], ['user_id'])
def get_users_groups(token_info: dict, user_id: str):
    next_token, per_page = get_next_token(request.args)
    user = User(user_id)
    return get_page(user.get_groups, next_token, per_page, 'groups')


@authorize(['fus:PutGroup'], ['arn:hca:fus:*:*:user/{user_id}/groups'], ['user_id'])
def put_users_groups(token_info: dict, user_id: str):
    user = User(user_id)
    resp, code = _modify_groups(user, request)
    return make_response(jsonify(resp), code)


@authorize(['fus:GetRole'], ['arn:hca:fus:*:*:user/{user_id}/roles'], ['user_id'])
def get_users_roles(token_info: dict, user_id: str):
    next_token, per_page = get_next_token(request.args)
    user = User(user_id)
    return get_page(user.get_roles, next_token, per_page, 'roles')


@authorize(['fus:PutRole'], ['arn:hca:fus:*:*:user/{user_id}/roles'], ['user_id'])
def put_users_roles(token_info: dict, user_id: str):
    user = User(user_id)
    resp, code = _modify_roles(user, request)
    return make_response(jsonify(resp), code)
