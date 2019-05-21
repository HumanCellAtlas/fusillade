from flask import request, make_response, jsonify
from fusillade import User, directory
from fusillade.utils.authorize import assert_authorized


def put_new_user(token_info:dict):
    json_body = request.json
    assert_authorized(token_info['https://auth.data.humancellatlas.org/email'],
                      ['fus:PutUser'],
                      [f'arn:hca:fus:*:*:user/{json_body["user_id"]}/'])
    user = User.provision_user(directory, json_body['user_id'], statement=json_body.get('policy'))
    user.add_roles(json_body.get('roles', []))
    user.add_groups(json_body.get('groups', []))
    return make_response('', 201)

def get_user(token_info:dict, user_id:str):
    assert_authorized(token_info['https://auth.data.humancellatlas.org/email'],
                      ['fus:GetUser'],
                      [f'arn:hca:fus:*:*:user/{user_id}/'])
    user = User(directory, user_id)
    return make_response(jsonify(name=user.name, status=user.status, policy=user.statement), 200)

def put_user(toeken_info:dict,user_id:str):
    assert_authorized(token_info['https://auth.data.humancellatlas.org/email'],
                      ['fus:PutUser'],
                      [f'arn:hca:fus:*:*:user/{user_id}/status'])
    user = User(directory, user_id)
    new_status = request.args['status']
    if new_status == 'enabled':
        user.enable()
        resp = make_response('', 200)
    elif new_status == 'disabled':
        user.disable()
        resp = make_response('', 200)
    else:
        resp = make_response('', 500)
    return resp


def put_user_policy(user_id):
    user = User(directory, user_id)
    user.statement = request.json['policy']
    return make_response('', 200)


def get_users_groups(user_id):
    user = User(directory, user_id)
    return make_response(jsonify(groups=user.groups), 200)


def put_users_groups(user_id):
    user = User(directory, user_id)
    action = request.args['action']
    if action == 'add':
        user.add_groups(request.json['groups'])
    elif action == 'remove':
        user.remove_groups(request.json['groups'])
    return make_response('', 200)


def get_users_roles(user_id):
    user = User(directory, user_id)
    return make_response(jsonify(roles=user.roles), 200)


def put_users_roles(user_id):
    user = User(directory, user_id)
    action = request.args['action']
    if action == 'add':
        user.add_roles(request.json['roles'])
    elif action == 'remove':
        user.remove_roles(request.json['roles'])
    return make_response('', 200)
