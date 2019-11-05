#!/usr/bin/env python
"""
Create a backup of Clouddirectory and output the file ro backup.json
"""

import json
import os
import sys
import typing

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.clouddirectory import User, Group, Role, CloudNode


def format_policies(policies: typing.List[typing.Tuple[str, str]]) -> typing.Dict[str, str]:
    rv = dict()
    for t, p in policies:
        if not p:
            continue
        else:
            rv[t] = json.loads(p)
    return rv


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
            'policies': format_policies([(p, user.get_policy(p)) for p in user.allowed_policy_types]),
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
            'policies': format_policies([(p, group.get_policy(p)) for p in group.allowed_policy_types]),
            'owners': group.list_owners(),
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
            'policies': format_policies([(p, role.get_policy(p)) for p in role.allowed_policy_types]),
            'owners': role.list_owners()
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


if __name__ == "__main__":
    backup()
