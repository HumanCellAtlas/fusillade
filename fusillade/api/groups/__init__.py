from flask import request, make_response, jsonify

from fusillade import directory, Group



def put_new_group():
    json_body = request.json
    group = Group.create(directory, json_body['name'], statement=json_body.get('policy'))
    group.add_roles(json_body.get('roles', []))  # Determine what response to return if roles don't exist
    return make_response("", 201)



def get_groups():
    pass



def get_group(group_id):
    group = Group(directory, group_id, local=True)
    return make_response(jsonify(name=group.name, policy=group.statement), 200)



def put_group_policy(group_id):
    group = Group(directory, group_id, local=True)
    group.statement = request.json['policy']
    return make_response("", 200)



def get_group_users(group_id):
    pass



def get_groups_roles(group_id):
    group = Group(directory, group_id, local=True)
    return make_response(jsonify(roles=group.roles), 200)



def put_groups_roles(group_id):
    group = Group(directory, group_id, local=True)
    action = request.args['action']
    if action == 'add':
        group.add_roles(request.json['roles'])
    elif action == 'remove':
        group.remove_roles(request.json['roles'])
    return make_response('', 200)



def delete_group(group_id):
    pass