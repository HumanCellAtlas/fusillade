#!/usr/bin/env python
"""
Create a backup of Clouddirectory in AWS S3.
"""
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
    # TODO list all users
    for name in list_node(User, 'users'):
        user = User(name)
        info = {
            'name': user.name,
            'status': user.status,
            'policies': user.attached_policies}
        users.append(info)
        print(info)
    return users


def backup_groups():
    groups = []
    for name in list_node(Group, 'groups'):
        group = Group(name)
        info = {
            'name': group.name,
            'members': [User(object_ref=u).name for u in group.get_users_iter()],
            'policies': group.attached_policies,
            'owners': [User(object_ref=u).name for u in group.list_owners()]
        }
        groups.append(info)
        print(info)
    return groups

def backup_roles():
    roles = []
    for name in list_node(Role, 'roles'):
        role = Role(name)
        members = role.cd.list_object_children(role.object_ref)
        for member in members:

        info = {
            'name': role.name,
            'owners': role.list_owners(),
        }

def backup():
    # users = backup_users()
    # groups = backup_groups()

    # TODO backup roles

# TODO we need backup format
# TODO we need a location to backup too

backup()