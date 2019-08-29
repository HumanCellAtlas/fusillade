import requests

from fusillade.clouddirectory import cd_client, Group, Role, User
from fusillade.errors import FusilladeLimitException, FusilladeHTTPException


def _modify_roles(cloud_node, request):
    action = request.args['action']
    resp = {'roles': request.json['roles'],
            'action': action,
            f'{cloud_node.object_type}_id': cloud_node.name
            }
    try:
        Role.exists(request.json['roles'])
        if action == 'add':
            cloud_node.add_roles(request.json['roles'])
        elif action == 'remove':
            cloud_node.remove_roles(request.json['roles'])
    except cd_client.exceptions.BatchWriteException as ex:
        # TODO inspect the error. Return 304 if link exists error. Return 404 if object does not exist error.
        resp['msg'] = ex.response['Error']['Message']
        code = 304
    else:
        resp['msg'] = f"{cloud_node.object_type}'s roles successfully modified."
        code = 200
    return resp, code


def _modify_groups(cloud_node, request):
    action = request.args['action']
    resp = {'groups': request.json['groups'],
            'action': action,
            f'{cloud_node.object_type}_id': cloud_node.name
            }
    try:
        Group.exists(request.json['groups'])
        if action == 'add':
            cloud_node.add_groups(request.json['groups'])
        elif action == 'remove':
            cloud_node.remove_groups(request.json['groups'])
    except cd_client.exceptions.BatchWriteException as ex:
        resp['msg'] = ex.response['Error']['Message']
        code = 304
    except FusilladeLimitException as ex:
        raise FusilladeHTTPException(detail=ex.reason, status=requests.codes.conflict, title="Conflict")
    else:
        resp['msg'] = f"{cloud_node.object_type}'s groups successfully modified."
        code = 200
    return resp, code


def _modify_users(cloud_node, request):
    action = request.args['action']
    resp = {'users': request.json['users'],
            'action': action,
            f'{cloud_node.object_type}_id': cloud_node.name
            }
    try:
        User.exists(request.json['users'])
        if action == 'add':
            cloud_node.add_users(request.json['users'])
        elif action == 'remove':
            cloud_node.remove_users(request.json['users'])
    except cd_client.exceptions.BatchWriteException as ex:
        resp['msg'] = ex.response['Error']['Message']
        code = 304
    else:
        resp['msg'] = f"{cloud_node.object_type}'s users successfully modified."
        code = 200
    return resp, code
