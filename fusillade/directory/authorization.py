from typing import List, Union

from fusillade import Config
from fusillade.directory import User, Group
from fusillade.directory.resource import ResourceId, ResourceType
from fusillade.errors import FusilladeForbiddenException
from fusillade.policy.resource_policy import combine


def get_resource_authz_parameters(user: str, resources: Union[List[str], str]):
    """

    Get all policy ids, and send them to lookup policy, group them by policy type.

    :param user:
    :param resource:
    :return:
    """
    policies = []
    _user = User(user)
    # Only support a single resource for now
    resource = resources[0] if isinstance(resources, list) else resources
    r_type, r_id, *_ = resource.split(':')[-1].split('/')
    if r_type in ResourceType.get_types():
        r_id = ResourceId(r_type, r_id)
        resource_policies = r_id.check_access([_user] + [Group(g) for g in _user.groups])
        if not resource_policies:
            raise FusilladeForbiddenException()
        policies.extend(resource_policies)
    policies.extend(list(_user.get_policy_ids()))
    authz_params = Config.get_directory().get_policies(policies)
    if authz_params.get('ResourcePolicy'):
        authz_params['ResourcePolicy'] = combine([i['policy_document'] for i in authz_params.get('ResourcePolicy')])
    return authz_params
