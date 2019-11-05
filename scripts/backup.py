#!/usr/bin/env python
"""
Create a backup of Clouddirectory in AWS S3.
"""
import json
import os
import sys

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.clouddirectory import User, Group, Role


def list_node(node, field):
    result, next_token = node.list_all(None, None)
    while True:
        for i in result[field]:
            yield i
        if next_token:
            result, next_token = node.list_all(next_token, None)
        else:
            break


def backup_users():
    users = []
    for name in list_node(User, 'users'):
        user = User(name)
        info = {
            'name': user.name,
            'status': user.status,
            'policies': [{p: json.loads(user.get_policy(p))} for p in user.allowed_policy_types],
            'roles': [Role(object_ref=r).name for r in user.roles]
        }
        users.append(info)
    print("USERS:", *users, sep='\n\t')
    return users


def backup_groups():
    groups = []
    for name in list_node(Group, 'groups'):
        group = Group(name)
        info = {
            'name': group.name,
            'members': [User(object_ref=u).name for u in group.get_users_iter()],
            'policies': [{p: json.loads(group.get_policy(p))} for p in group.allowed_policy_types],
            'owners': [User(object_ref=u).name for u in group.list_owners()],
            'roles': [Role(object_ref=r).name for r in group.roles]
        }
        groups.append(info)
    print("GROUPS:", *groups, sep='\n\t')
    return groups


def backup_roles():
    roles = []
    for name in list_node(Role, 'roles'):
        role = Role(name)
        info = {
            'name': role.name,
            'owners': [User(object_ref=u).name for u in role.list_owners()],
            'policies': [{p: json.loads(role.get_policy(p))} for p in role.allowed_policy_types]
        }
        roles.append(info)
    print("ROLES:", *roles, sep='\n\t')
    return roles


def backup():
    with open('backup.json', 'w') as fp:
        json.dump(
            dict(
                users=backup_users(),
                groups=backup_groups(),
                roles=backup_roles()),
            fp,
            indent=2)


backup()
