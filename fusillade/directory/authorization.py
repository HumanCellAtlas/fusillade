from typing import Type

from fusillade.directory import User, Group
from fusillade.directory.resource import ResourceId


def get_resource_authz_parameters(user: str, resource: str):
    get_authz_params = User(user).get_policy_ids()
    r_type, r_id, *_ = resource.split(':')[-1].split('/')
    resource_policies = ResourceId(r_type, r_id).get_access_policies(
        [user] + [Group(g) for g in user.groups])
