import json
import logging
import os
from typing import Dict, Union, List, Any, Optional, Type, Set, Tuple

import itertools

from dcplib.aws.clients import clouddirectory as cd_client
from fusillade import Config
from fusillade.config import proj_path
from fusillade.directory.cloudnode import CloudNode
from fusillade.directory.identifiers import get_obj_type_path
from fusillade.directory.structs import ConsistencyLevel, UpdateObjectParams, ValueTypes, UpdateActions
from fusillade.errors import FusilladeHTTPException, FusilladeNotFoundException, AuthorizationException, \
    FusilladeLimitException
from fusillade.policy.validator import verify_policy
from fusillade.utils.json import get_json_file

logger = logging.getLogger(__name__)


class PolicyMixin:
    """Adds policy support to a cloudNode"""
    allowed_policy_types = ['IAMPolicy']

    def get_authz_params(self) -> Dict[str, Union[List[Dict[str, str]], List[str]]]:
        policy_paths = self.cd.lookup_policy(self.object_ref)
        policy_ids = self.cd.get_policy_ids(policy_paths)
        return self.cd.get_policies(policy_ids)

    def create_policy(self, statement: Dict[str, Any],
                      policy_type='IAMPolicy', run=True, **kwargs) -> Union[List, None]:
        """
        Create a policy object and attach it to the CloudNode
        :param statement: Json that follow AWS IAM Policy Grammar.
          https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
        :param policy_type:
        :return:
        """
        operations = list()
        verify_policy(statement, policy_type)
        object_attribute_list = self.cd.get_policy_attribute_list('IAMPolicy', statement, **kwargs)
        policy_link_name = self.get_policy_name(policy_type)
        parent_path = get_obj_type_path('policy')
        operations.append(
            {
                'CreateObject': {
                    'SchemaFacet': [
                        {
                            'SchemaArn': self.cd.schema,
                            'FacetName': policy_type
                        },
                        {
                            'SchemaArn': self.cd.node_schema,
                            'FacetName': 'POLICY'
                        },
                    ],
                    'ObjectAttributeList': object_attribute_list,
                    'ParentReference': {
                        'Selector': parent_path
                    },
                    'LinkName': policy_link_name,
                }
            }
        )
        policy_ref = parent_path + policy_link_name

        operations.append(self.cd.batch_attach_policy(policy_ref, self.object_ref))
        if run:
            self.cd.batch_write(operations)
            logger.info(dict(message="Policy created",
                             object=dict(
                                 type=self.object_type,
                                 path_name=self._path_name
                             ),
                             policy=dict(
                                 link_name=policy_link_name,
                                 policy_type=policy_type)
                             ))
        else:
            return operations

    def get_policy_name(self, policy_type):
        return self.hash_name(f"{self._path_name}{self.object_type}{policy_type}")

    def get_policy(self, policy_type: str = 'IAMPolicy'):
        """
        Policy statements follow AWS IAM Policy Grammer. See for grammar details
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
        """
        if policy_type in self.allowed_policy_types:  # check if this policy type is allowed
            if not self.attached_policies.get(policy_type):  # check if we already have the policy
                policy_ref = get_obj_type_path('policy') + self.get_policy_name(policy_type)
                try:
                    resp = self.cd.get_object_attributes(
                        policy_ref,
                        'POLICY',
                        ['policy_document', 'policy_type'],
                        self.cd.node_schema
                    )
                    attrs = dict([(attr['Key']['Name'], attr['Value'].popitem()[1]) for attr in resp['Attributes']])
                    if attrs['policy_type'] != policy_type:
                        logger.warning({'message': "Retrieved policy_type does not match requested policy_type.",
                                        'expected': policy_type,
                                        'received': attrs['policy_type']
                                        })
                    self.attached_policies[policy_type] = json.loads(attrs['policy_document'].decode("utf-8"))
                except cd_client.exceptions.ResourceNotFoundException:
                    pass
            return self.attached_policies.get(policy_type, {})
        else:
            FusilladeHTTPException(
                title='Bad Request',
                detail=f"{self.object_type} cannot have policy type {policy_type}."
                f" Allowed types are: {self.allowed_policy_types}")

    def set_policy(self, statement: Dict[Any, str], policy_type: str = 'IAMPolicy'):
        if policy_type in self.allowed_policy_types:
            try:
                # check if this object exists
                self.cd.get_object_information(self.object_ref, ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name)
            except cd_client.exceptions.ResourceNotFoundException:
                raise FusilladeNotFoundException(detail="Resource does not exist.")
            else:
                self._set_policy(statement, policy_type)

    def _set_policy(self, statement: Dict[str, Any], policy_type: str = 'IAMPolicy'):
        verify_policy(statement, policy_type)
        params = [
            UpdateObjectParams('POLICY',
                               'policy_document',
                               ValueTypes.BinaryValue,
                               self.cd.format_policy(statement),
                               UpdateActions.CREATE_OR_UPDATE,
                               )
        ]
        try:
            try:
                self.cd.update_object_attribute(get_obj_type_path('policy') + self.get_policy_name(policy_type),
                                                params,
                                                self.cd.node_schema)
            except cd_client.exceptions.ResourceNotFoundException:
                self.create_policy(statement, policy_type, type=self.object_type, name=self.name)
        except cd_client.exceptions.LimitExceededException as ex:
            raise FusilladeHTTPException(ex)
        else:
            logger.info(dict(message="Policy updated",
                             object=dict(
                                 type=self.object_type,
                                 path_name=self._path_name
                             ),
                             policy=dict(
                                 link_name=self.get_policy_name(policy_type),
                                 policy_type=policy_type)
                             ))

        self.attached_policies[policy_type] = None

    def get_policy_info(self):
        return {'policies': dict([(i, self.get_policy(i)) for i in self.allowed_policy_types if self.get_policy(i)])}


class CreateMixin(PolicyMixin):
    """Adds creation support to a cloudNode"""

    @classmethod
    def create(cls,
               name: str,
               statement: Optional[Dict[str, Any]] = None,
               creator=None,
               **kwargs) -> Type['CloudNode']:
        ops = []
        new_node = cls(name)
        _creator = creator if creator else "fusillade"
        ops.append(new_node.cd.batch_create_object(
            get_obj_type_path(cls.object_type),
            new_node.hash_name(name),
            new_node._facet,
            new_node.cd.get_object_attribute_list(facet=new_node._facet, name=name, created_by=_creator, **kwargs)
        ))
        if creator:
            ops.append(User(name=creator).batch_add_ownership(new_node))

        if not statement and not getattr(cls, '_default_policy_path', None):
            pass
        else:
            if not statement:
                statement = get_json_file(cls._default_policy_path)
            ops.extend(new_node.create_policy(statement, run=False, type=new_node.object_type, name=new_node.name))

        try:
            new_node.cd.batch_write(ops)
        except cd_client.exceptions.BatchWriteException as ex:
            if 'LinkNameAlreadyInUseException' in ex.response['Error']['Message']:
                raise FusilladeHTTPException(
                    status=409, title="Conflict", detail=f"The {cls.object_type} named {name} already exists. "
                    f"{cls.object_type} was not modified.")
            else:
                raise FusilladeHTTPException(ex)
        else:
            new_node.cd.get_object_information(new_node.object_ref, ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name)
            logger.info(dict(message=f"{new_node.object_type} created by {_creator}",
                             object=dict(type=new_node.object_type, path_name=new_node._path_name)))
            logger.info(dict(message="Policy updated",
                             object=dict(
                                 type=new_node.object_type,
                                 path_name=new_node._path_name
                             ),
                             policy=dict(
                                 link_name=new_node.get_policy_name('IAMPolicy'),
                                 policy_type='IAMPolicy')
                             ))
            return new_node


class RolesMixin:
    """Adds role support to a cloudNode"""

    @property
    def roles(self) -> List[str]:
        if not self._roles:
            self._roles = self._get_links(Role,
                                          self.cd.make_filter_attribute_range('member_of',
                                                                              Role.object_type,
                                                                              Role.object_type),
                                          'membership_link',
                                          incoming=False)
        return self._roles

    def get_roles(self, next_token: str = None, per_page: str = None):
        result, next_token = self._get_links(Role,
                                             self.cd.make_filter_attribute_range('member_of',
                                                                                 Role.object_type,
                                                                                 Role.object_type),
                                             'membership_link',
                                             paged=True,
                                             next_token=next_token,
                                             per_page=per_page)
        return {'roles': result}, next_token

    def add_roles(self, roles: List[str]):
        operations = []
        _roles = [Role(role) for role in roles]
        operations.extend(self._add_links_batch(_roles))
        operations.extend(self._add_typed_links_batch(_roles,
                                                      'membership_link',
                                                      {'member_of': Role.object_type}))
        self.cd.batch_write(operations)
        self._roles = None  # update roles
        logger.info(dict(message="Roles added",
                         object=dict(type=self.object_type, path_name=self._path_name),
                         roles=roles))

    def remove_roles(self, roles: List[str]):
        operations = []
        _roles = [Role(role) for role in roles]
        operations.extend(self._remove_links_batch(_roles))
        operations.extend(self._remove_typed_links_batch(_roles,
                                                         'membership_link',
                                                         {'member_of': Role.object_type}))
        self.cd.batch_write(operations)
        self._roles = None  # update roles
        logger.info(dict(message="Roles removed",
                         object=dict(type=self.object_type, path_name=self._path_name),
                         roles=roles))


class OwnershipMixin:
    ownable = ['group', 'role']

    def add_ownership(self, node: Type['CloudNode']):
        self.cd.attach_typed_link(
            self.object_ref,
            node.object_ref,
            'ownership_link',
            {'owner_of': node.object_type})

    def batch_add_ownership(self, node: Type['CloudNode']) -> Dict:
        return self.cd.batch_attach_typed_link(
            self.object_ref,
            node.object_ref,
            'ownership_link',
            {'owner_of': node.object_type}
        )

    def remove_ownership(self, node: Type['CloudNode']):
        typed_link_specifier = self.cd.make_typed_link_specifier(
            self.object_ref,
            node.object_ref,
            'ownership_link',
            {'owner_of': node.object_type}
        )
        self.cd.detach_typed_link(typed_link_specifier)

    def batch_remove_ownership(self, node: Type['CloudNode']) -> Dict:
        typed_link_specifier = self.cd.make_typed_link_specifier(
            self.object_ref,
            node.object_ref,
            'ownership_link',
            {'owner_of': node.object_type}
        )
        return self.cd.batch_detach_typed_link(typed_link_specifier)

    def is_owner(self, node: Type['CloudNode']):
        tls = self.cd.make_typed_link_specifier(
            self.object_ref,
            node.object_ref,
            'ownership_link',
            {'owner_of': node.object_type})
        try:
            self.cd.get_link_attributes(tls, [])
        except cd_client.exceptions.ResourceNotFoundException:
            return False
        else:
            return True

    def list_owned(self, node: Type['CloudNode'], **kwargs):
        result, next_token = self._get_links(node,
                                             self.cd.make_filter_attribute_range('owner_of',
                                                                                 node.object_type,
                                                                                 node.object_type),
                                             'ownership_link',
                                             incoming=False,
                                             **kwargs)
        return {f"{node.object_type}s": result}, next_token

    def get_owned(self, object_type, **kwargs):
        if object_type in self.ownable:
            if object_type == 'group':
                return self.list_owned(Group, **kwargs)
            if object_type == 'role':
                return self.list_owned(Role, **kwargs)


class Principal(CloudNode, RolesMixin, CreateMixin, OwnershipMixin):
    """
    Represents a principal in CloudDirectory. A principal is any one who can assume roles, and own resources.
    """
    _facet = 'LeafFacet'


default_group_policy_path = os.path.join(proj_path, '..', 'policies', 'default_group_policy.json')
default_role_path = os.path.join(proj_path, '..', 'policies', 'default_role.json')


class User(Principal):
    """
    Represents a user in CloudDirectory
    """
    _attributes = ['status'] + CloudNode._attributes
    default_roles = []  # TODO: make configurable
    default_groups = ['user_default']  # TODO: make configurable
    object_type = 'user'

    def __init__(self, name: str = None, object_ref: str = None):
        """

        :param name:
        """
        super(User, self).__init__(name=name,
                                   object_ref=object_ref)
        self._status = None
        self._groups: Optional[List[str]] = None
        self._roles: Optional[List[str]] = None

    def get_authz_params(self) -> Dict[str, Union[List[Dict[str, str]], List[str]]]:
        return self.cd.get_policies(self.get_policy_ids())

    def get_policy_ids(self) -> Dict[str, Union[List[Dict[str, str]], List[str]]]:
        if self.is_enabled():
            policy_paths = self.lookup_policies_batched()
        else:
            raise AuthorizationException(f"User {self.status}")
        return self.cd.get_policy_ids(policy_paths)

    def lookup_policies_batched(self):
        object_refs = self.groups + [self.object_ref]
        operations = [self.cd.batch_lookup_policy(object_ref) for object_ref in object_refs]
        all_results = []
        while True:
            results = [r['SuccessfulResponse']['LookupPolicy'] for r in self.cd.batch_read(operations)['Responses']]
            ops_index_modifier = 0
            for i in range(len(results)):
                all_results.extend(results[i]['PolicyToPathList'])  # get results
                if results[i].get('NextToken'):
                    operations[i - ops_index_modifier]['LookupPolicy']['NextToken'] = results[i]['NextToken']
                else:
                    operations.pop(i - ops_index_modifier)
                    ops_index_modifier += 1
            if not operations:
                break
        return all_results

    def get_actions(self) -> Set[str]:
        """
        Retrieve the actions the user is allowed to perform
        :return: a set of actions the users can perform
        """
        statements = list(itertools.chain.from_iterable(
            [json.loads(p['policy_document'])['Statement'] for p in self.get_authz_params()['IAMPolicy']]))
        actions = list(itertools.chain.from_iterable([s['Action'] for s in statements if s['Effect'] == 'Allow']))

        # Need to handle cases where the actions has a wildcard. All actions that match the wildcard are removed and
        # only the wildcard value will remain. TODO: investigate if this is worth the headache if managing.
        prefixes = []
        for a in actions:
            if a.endswith('*'):
                prefixes.append(a)
        prefixes.sort(key=len, reverse=True)
        if prefixes:
            for prefix in prefixes:
                i = 0
                while i < len(actions):
                    if prefix == actions[i]:
                        i += 1
                    elif actions[i].startswith(prefix[:-1]):
                        actions.pop(i)
                    else:
                        i += 1
        return set(actions)

    @property
    def status(self):
        if not self._status:
            self._get_attributes(['status'])
        return self._status

    def is_enabled(self) -> bool:
        """
        Check if the user is enabled. Create the users with defaults if the user does not exist already.
        :return: users status
        """
        try:
            # check if the node has been created in cloud directory.
            result = self.status == 'Enabled'
        except FusilladeNotFoundException:
            # node does not exist, create the node.
            self.provision_user(self.name)
            result = self.is_enabled()
        return result

    def enable(self):
        """change the status of a user to enabled"""
        update_params = [
            UpdateObjectParams(self._facet,
                               'status',
                               ValueTypes.StringValue,
                               'Enabled',
                               UpdateActions.CREATE_OR_UPDATE)
        ]
        self.cd.update_object_attribute(self.object_ref, update_params)
        logger.info(dict(message="User Enabled", object=dict(type=self.object_type, path_name=self._path_name)))
        self._status = None

    def disable(self):
        """change the status of a user to disabled"""
        update_params = [
            UpdateObjectParams(self._facet,
                               'status',
                               ValueTypes.StringValue,
                               'Disabled',
                               UpdateActions.CREATE_OR_UPDATE)
        ]
        self.cd.update_object_attribute(self.object_ref, update_params)
        logger.info(dict(message="User Disabled", object=dict(type=self.object_type, path_name=self._path_name)))
        self._status = None

    @classmethod
    def provision_user(
            cls,
            name: str,
            statement: Optional[Dict[str, Any]] = None,
            roles: List[str] = None,
            groups: List[str] = None,
            creator: str = None
    ) -> 'User':
        """
        Creates a user in cloud directory if the users does not already exists.

        :param name:
        :param statement:
        :param roles:
        :param groups:
        :return:
        """
        user = cls(name)
        _creator = creator if creator else None

        # verify parameters
        if roles:
            Role.exists(roles)
        if groups:
            Group.exists(groups)

        user = User.create(name, statement, creator=_creator, status='Enabled')

        roles = roles + cls.default_roles if roles else cls.default_roles
        user.add_roles(roles)

        groups = groups + cls.default_groups if groups else cls.default_groups
        user.add_groups(groups)
        return user

    @property
    def groups(self) -> List[str]:
        if not self._groups:
            self._groups = self._get_links(Group,
                                           self.cd.make_filter_attribute_range('member_of',
                                                                               Group.object_type,
                                                                               Group.object_type),
                                           'membership_link')
        return self._groups

    def get_groups(self, next_token: str = None, per_page: int = None):
        result, next_token = self._get_links(Group,
                                             self.cd.make_filter_attribute_range('member_of',
                                                                                 Group.object_type,
                                                                                 Group.object_type),
                                             'membership_link',
                                             paged=True,
                                             next_token=next_token,
                                             per_page=per_page)
        return {'groups': result}, next_token

    def add_groups(self, groups: List[str], run=True):
        operations = []
        if len(self.groups) + len(groups) >= Config.group_max:
            raise FusilladeLimitException(
                f"Failed to add groups [{groups}]. The user belongs to {len(self.groups)} groups. "
                f"Only {Config.group_max - len(self.groups)} can be added.")
        operations.extend(self._add_typed_links_batch([Group(group) for group in groups],
                                                      'membership_link',
                                                      {'member_of': Group.object_type}))
        if run:
            self.cd.batch_write(operations)
            self._groups = None  # update groups
            logger.info(dict(message="Groups joined",
                             object=dict(type=self.object_type, path_name=self._path_name),
                             groups=groups))
        else:
            return operations

    def remove_groups(self, groups: List[str], run=True):
        operations = []
        operations.extend(self._remove_typed_links_batch([Group(group) for group in groups],
                                                         'membership_link',
                                                         {'member_of': Group.object_type}))
        if run:
            self.cd.batch_write(operations)
            self._groups = None  # update groups
            logger.info(dict(message="Groups left",
                             object=dict(type=self.object_type, path_name=self._path_name),
                             groups=groups))
        else:
            return operations

    def get_info(self):
        info = super(User, self).get_info()
        info.update(super(User, self).get_policy_info())
        info['status'] = self.status
        return info

    @classmethod
    def exists(cls, users: List[str]):
        cls._exists(users)


class Group(Principal):
    """
    Represents a group in CloudDirectory
    """
    object_type = 'group'
    _default_policy_path = default_group_policy_path

    def __init__(self, name: str = None, object_ref: str = None):
        """

        :param name:
        """
        super(Group, self).__init__(name=name, object_ref=object_ref)
        self._roles: Optional[List[str]] = None

    def get_users_iter(self) -> Tuple[Dict[str, Union[list, Any]], Any]:
        """
        Retrieves the object_refs for all user in this group.
        :return: (user name, user object reference)
        """
        return self._get_links(
            User,
            self.cd.make_filter_attribute_range('member_of',
                                                self.object_type,
                                                self.object_type),
            'membership_link',
            incoming=True)

    def get_users_page(self, next_token=None, per_page=None) -> Tuple[Dict, str]:
        """
        Retrieves the object_refs for all user in this group.
        :return: (user name, user object reference)
        """
        results, next_token = self._get_links(
            User,
            self.cd.make_filter_attribute_range('member_of',
                                                self.object_type,
                                                self.object_type),
            'membership_link',
            paged=True,
            per_page=per_page,
            incoming=True,
            next_token=next_token)
        return {'users': results}, next_token

    def add_users(self, users: List[str]) -> None:
        if users:
            operations = list(itertools.chain(*[User(user).add_groups([self.name], False) for user in users]))
            self.cd.batch_write(operations)
            logger.info(dict(message="Adding users to group",
                             object=dict(type=self.object_type, path_name=self._path_name),
                             users=users))

    def remove_users(self, users: List[str]) -> None:
        """
        Removes users from this group.

        :param users: a list of user names to remove from group
        :return:
        """
        if users:
            operations = list(itertools.chain(*[User(user).remove_groups([self.name], False) for user in users]))
            self.cd.batch_write(operations)
            logger.info(dict(message="Removing users from group",
                             object=dict(type=self.object_type, path_name=self._path_name),
                             users=[user for user in users]))

    def get_info(self):
        info = super(Group, self).get_info()
        info.update(self.get_policy_info())
        return info

    @classmethod
    def exists(cls, groups: List[str]):
        cls._exists(groups)


class Role(CloudNode, CreateMixin):
    """
    Represents a role in CloudDirectory
    """
    _facet: str = 'NodeFacet'
    object_type: str = 'role'
    _default_policy_path: str = default_role_path

    def get_info(self):
        info = super(Role, self).get_info()
        info.update(self.get_policy_info())
        return info

    @classmethod
    def exists(cls, roles: List[str]):
        cls._exists(roles)
