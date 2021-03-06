"""
## ResourceType
The ResourceType class is an abstraction of a node in cloud directory that represents a type of resource we would like
to apply access control logic (ACL).

### Actions
This type of resource has certain action that can be performed on or with it, and these actions are store in an
attribute called `actions`. Any access policy associated with this resource type must only include actions that the
resource supports. This is checked before new policies are added, and nonconforming resource_policy are rejected. If an
actions is removed from the resource type all existing resource_policy with this action will be removed.

### Owner policy
The owner policy is added to the resource type and is used to determine what actions the owner of a resource Id can
perform on a resource.
"""
import json
import logging
import os
from collections import defaultdict, deque
from typing import List, Dict, Any, Type, Union, Tuple

from dcplib.aws.clients import clouddirectory as cd_client
from fusillade.config import proj_path, Config
from fusillade.directory.cloudnode import CloudNode
from fusillade.directory.identifiers import get_obj_type_path
from fusillade.directory.principal import Principal, User, Group
from fusillade.directory.structs import ConsistencyLevel, UpdateObjectParams, ValueTypes, UpdateActions
from fusillade.errors import FusilladeHTTPException, FusilladeNotFoundException, FusilladeBadRequestException
from fusillade.policy.validator import verify_policy

logger = logging.getLogger(__name__)
default_resource_owner_policy = os.path.join(proj_path, '..', 'policies', 'default_resource_owner_policy.json')


class ResourceType(CloudNode):
    _attributes = ['actions'] + CloudNode._attributes
    _facet: str = 'NodeFacet'
    object_type: str = 'resource'
    _default_policy_path: str = default_resource_owner_policy
    policy_type = 'ResourcePolicy'
    _resource_types: List[str] = None

    def __init__(self, *args, **kwargs):
        super(ResourceType, self).__init__(*args, **kwargs)
        self._actions: str = None

    @classmethod
    def create(cls,
               name: str,
               actions: List[str],
               owner_policy: Dict[str, Any] = None,
               creator: str = None,
               **kwargs) -> 'ResourceType':
        """
        Create a new resource type in cloud directory.

        :param name: The name of the new resource type.
        :param owner_policy: an IAM policy that determines what a resource owner can do to a resource.
        :param creator: The user who initiated the creation of the resource type.
        :param actions: The actions that can be performed on this resource type
        :param kwargs: additional attributes describing the resource type.
        :return:
        """
        ops = []
        new_node = cls(name)
        _creator = creator if creator else "fusillade"
        # Create the node /resource/{resource_type}
        ops.append(new_node.cd.batch_create_object(
            get_obj_type_path(cls.object_type),
            name,
            new_node._facet,
            new_node.cd.get_object_attribute_list(facet=new_node._facet,
                                                  name=name,
                                                  created_by=_creator,
                                                  actions=' '.join(actions),
                                                  # TODO actions should also have descriptions
                                                  **kwargs),
            batch_reference='type_node'
        ))
        # Create the node /resource/{resource_type}/id
        ops.append(
            new_node.cd.batch_create_object(
                '#type_node',
                'id',
                'NodeFacet',
                new_node.cd.get_object_attribute_list(facet='NodeFacet', name='id', created_by=_creator)
            ))
        # Create the node /resource/{resource_type}/policy
        ops.append(
            new_node.cd.batch_create_object(
                '#type_node',
                'policy',
                'NodeFacet',
                new_node.cd.get_object_attribute_list(facet='NodeFacet', name='policy',
                                                      created_by=_creator),
                batch_reference='policy_node'
            ))
        # link owner policy to resource type
        if not owner_policy and not getattr(cls, '_default_policy_path', None):
            raise FusilladeHTTPException('Must provide owner policy.')
        else:
            if owner_policy:
                pass
            elif getattr(cls, '_default_policy_path'):
                with open(cls._default_policy_path, 'r') as fp:
                    owner_policy = json.load(fp)
            ops.extend(new_node.create_policy('Owner',
                                              owner_policy,
                                              parent_path='#policy_node',
                                              run=False))

        # Execute batch request
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
            new_node.cd.get_object_information(new_node.object_ref,
                                               ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name)
            logger.info(dict(message=f"{new_node.object_type} created by {_creator}",
                             object=dict(type=new_node.object_type, path_name=new_node._path_name)))
            logger.info(dict(message="Policy updated",
                             object=dict(
                                 type=new_node.object_type,
                                 path_name=new_node._path_name
                             ),
                             policy=dict(
                                 link_name='Owner',
                                 policy_type='IAMPolicy')
                             ))
            return new_node

    # TODO: Add function to modify actions, this will need to modify all resource_policy with this actions
    @property
    def actions(self):
        if not self._actions:
            self._get_attributes(self._attributes)
        if isinstance(self._actions, str):
            self._actions = self._actions.split(' ')
        return self._actions

    def add_actions(self, actions: List[str]):
        _actions = set(actions)
        _actions.update(self.actions)
        self.cd.update_object_attribute(self.object_ref,
                                        [UpdateObjectParams(
                                            self._facet,
                                            'actions',
                                            ValueTypes.StringValue,
                                            ' '.join(_actions),
                                            UpdateActions.CREATE_OR_UPDATE,
                                        )])
        self._actions = None

    def remove_actions(self, actions: List[str]):
        _actions = set(self.actions) - set(actions)
        self.cd.update_object_attribute(self.object_ref,
                                        [UpdateObjectParams(
                                            self._facet,
                                            'actions',
                                            ValueTypes.StringValue,
                                            ' '.join(_actions),
                                            UpdateActions.CREATE_OR_UPDATE,
                                        )])
        # TODO remove this actions from all resource_policy
        self._actions = None

    def check_actions(self, policy: dict):
        policy_actions = set()
        for s in policy['Statement']:
            policy_actions.update(s['Action'])
        if not policy_actions.issubset(set(self.actions)):
            raise FusilladeBadRequestException(
                detail=f"Invalid actions in policy. Allowed actions are {self.actions}")

    @classmethod
    def get_types(cls):
        if not cls._resource_types:
            cd = Config.get_directory()
            cls._resource_types = [name for name, _ in cd.list_object_children(f'/{cls.object_type}/')]
        return cls._resource_types

    @staticmethod
    def hash_name(name):
        """
        Overriding the hash_name function in CloudNode. No special hashing is done on resourceTypes.
        :param name:
        :return:
        """
        return name

    def list_policies(self, next_token=None, per_page=None) -> Dict[str, str]:
        children, next_token = self.cd.list_object_children_paged(f"{self.object_ref}/policy", next_token, per_page)
        return {'policies': [f"/resource/{self.name}/policy/{child}" for child in children.keys()]}, next_token

    def list_ids(self, next_token=None, per_page=None):
        children, next_token = self.cd.list_object_children_paged(f"{self.object_ref}/id", next_token, per_page)
        return (
            {
                'resource_ids': [f"/resource/{self.name}/id/{child}" for child in children.keys()],
                'resource_type': self.name
            },
            next_token)

    def get_policy_reference(self, policy_name: str) -> str:
        """Returns a policy reference that can be used by cloud directory"""
        return f"{self.object_ref}/policy/{policy_name}"

    def get_policy_path(self, policy_name: str):
        """Returns a human readable policy path"""
        return f"/resource/{self.name}/policy/{policy_name}"

    def create_policy(self,
                      policy_name: str,
                      policy: dict,
                      policy_type: str = 'IAMPolicy',
                      parent_path: str = None,
                      run=True,
                      **kwargs) -> Union[None, List[Dict[str, Any]]]:
        """
        Create a policy object and attach it to the ResourceType.

        :param policy_name:
        :param policy: Json string that follow AWS IAM Policy Grammar.
          https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
        :param policy_type: Either 'IAMPolicy' or 'ResourcePolicy'.
        :param parent_path: The cloud directory path to the parent node the policy will be attached. If None the
        policy is attached to /resource/{self.name}/policy
        :param run:
        :param kwargs: additional attributes describing the policy.
        :return:
        """
        if policy_type == "ResourcePolicy":
            self.check_actions(policy)
        verify_policy(policy, policy_type)
        operations = list()
        object_attribute_list = self.cd.get_policy_attribute_list(policy_type, policy, type=self.object_type,
                                                                  name=policy_name, **kwargs)
        parent_path = parent_path or f"{self.object_ref}/policy"
        batch_reference = f'new_policy_{policy_name}'
        operations.append(
            {
                'CreateObject': {
                    'SchemaFacet': [
                        {
                            'SchemaArn': self.cd.schema,
                            'FacetName': 'IAMPolicy'
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
                    'LinkName': policy_name,
                    'BatchReferenceName': batch_reference
                }
            }

        )

        if run:
            self.cd.batch_write(operations)
            logger.info(dict(message="Policy created",
                             object=dict(
                                 type='resource',
                                 path_name=f"{self._path_name}/policy"
                             ),
                             policy=dict(
                                 link_name=policy_name,
                                 policy_type=policy_type)
                             ))
        else:
            return operations

    def delete_policy(self, policy_name):
        try:
            self.cd.delete_object(self.get_policy_reference(policy_name))
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeNotFoundException(f"{self.get_policy_path(policy_name)} does not exist.")

    def update_policy(self, policy_name: str, policy: dict, policy_type: str):
        self.check_actions(policy)
        params = [
            UpdateObjectParams('POLICY',
                               'policy_document',
                               ValueTypes.BinaryValue,
                               self.cd.format_policy(policy),
                               UpdateActions.CREATE_OR_UPDATE,
                               )
        ]
        try:
            verify_policy(policy, policy_type)
            self.cd.update_object_attribute(self.get_policy_reference(policy_name),
                                            params,
                                            self.cd.node_schema)
        except cd_client.exceptions.LimitExceededException as ex:
            raise FusilladeHTTPException(ex)
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeNotFoundException(f"{self.get_policy_path(policy_name)} does not exist.")
        else:
            logger.info(dict(message="Policy updated",
                             object=dict(
                                 type=self.object_type,
                                 path_name=self._path_name
                             ),
                             policy=dict(
                                 link_name=policy_name,
                                 policy_type=policy_type)
                             ))

    def get_policy(self, policy_name):
        try:
            resp = self.cd.get_object_attributes(
                self.get_policy_reference(policy_name),
                'POLICY',
                ['policy_document', 'policy_type'],
                self.cd.node_schema
            )
            attrs = dict([(attr['Key']['Name'], attr['Value'].popitem()[1]) for attr in resp['Attributes']])
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeNotFoundException(f"{self.get_policy_path(policy_name)} does not exist.")
        attrs['policy'] = json.loads(attrs['policy_document'])
        attrs.pop('policy_document')
        return attrs

    def policy_exists(self, policy_name: str):
        try:
            self.cd.get_object_information(self.get_policy_reference(policy_name))
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeBadRequestException(f"{self.object_type}/{self.name}/policy/{policy_name} does not exist.")

    def delete_node(self):
        try:
            self.cd.delete_object(self.object_ref, delete_children=True)
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeNotFoundException(f"Failed to delete {self.name}. {self.object_type} does not exist.")

    def create_id(self, name: str, owner: str = None, **kwargs) -> 'ResourceId':
        return ResourceId.create(self.name, name, owner, **kwargs)

    def get_id(self, *args, **kwargs) -> 'ResourceId':
        return ResourceId(self.name, *args, **kwargs)

    def get_info(self) -> Dict[str, Any]:
        info = super(ResourceType, self).get_info()
        info[f'{self.object_type}_type'] = info.pop(f'{self.object_type}_id')
        return info


class ResourceId(CloudNode):
    """arn:*:resource/{resource_type}/{resource_id}"""

    _facet: str = 'NodeFacet'
    allowed_policy_types = ['Resource']

    def __init__(self, resource_type: str, *args, **kwargs):
        self.resource_type: ResourceType = ResourceType(resource_type)
        super(ResourceId, self).__init__(*args, **kwargs)
        self._principals = None  # update roles

    def from_name(self, name):
        self._name: str = name
        self._path_name: str = name
        self.object_ref: str = f'{get_obj_type_path(self.object_type)}{self._path_name}'

    @property
    def object_type(self):
        return f'resource/{self.resource_type.name}'

    @staticmethod
    def hash_name(name):
        return name

    @classmethod
    def create(cls, resource_type: str, name: str, owner: str = None, **kwargs) -> 'ResourceId':
        ops = []
        new_node = cls(resource_type, name=name)
        _owner = owner if owner else "fusillade"
        ops.append(new_node.cd.batch_create_object(
            f'{new_node.resource_type.object_ref}/id',
            new_node.name,
            new_node._facet,
            new_node.cd.get_object_attribute_list(facet=new_node._facet, name=name, created_by=_owner, **kwargs)
        ))
        if owner:
            ops.append(User(name=owner).batch_add_ownership(new_node))
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
            logger.info(dict(message=f"{new_node.object_type} created",
                             creator=_owner,
                             object=dict(type=new_node.object_type, path_name=new_node._path_name)))
            return new_node

    def list_principals(
            self,
            next_token: str = None,
            per_page: int = None) -> Tuple[Dict[str, List[Dict[str, str]]], str]:
        """
        List the principals that have some level of  access to this resource id.

        :param next_token:
        :param per_page:
        :return: JSON-formatted list of principals and a token for pagination
        """
        # retrieve the raw list of object references from cloud directory
        _results, next_token = self.cd.list_incoming_typed_links(self.object_ref, [], 'access_link',
                                                                 next_token=next_token, paged=True, per_page=per_page)
        result = deque()
        if _results:
            ops = []
            for r in _results:
                # retrieve the principal attribute from the `r`, this will be returned in the response.
                result.append({'member_type': self.cd.parse_attributes(r['IdentityAttributeValues'])['principal']})
                # build the batch_read request list to retrieve the rest of the attributes for the response
                # We need `access_level` from the typed link
                ops.append(self.cd.batch_get_link_attributes(r, ['access_level']))
                # and we need need `name` from the source object.
                ops.append(self.cd.batch_get_attributes(
                    r['SourceObjectReference']['Selector'],
                    Principal._facet,
                    ['name']))
                # There are two requests per `r` in `_results`

            # `switch` is used to retrieve the two responses per `r` in `_results`
            switch = True
            for resp in self.cd.batch_read(ops)['Responses']:
                # Below, temp stores the result we are working on. Once we have retrieved both responses and added
                # the relavent attributes to temp, we append back to the results. This is to sync the results with
                # the batch read responses.
                if resp.get('SuccessfulResponse'):
                    if switch:
                        temp = result.popleft()
                        temp.update(self.cd.parse_attributes(
                            resp['SuccessfulResponse']
                            ['GetLinkAttributes']
                            ['Attributes']))
                        switch = False
                    else:
                        temp['member'] = self.cd.parse_attributes(
                            resp['SuccessfulResponse']
                            ['GetObjectAttributes']
                            ['Attributes'])['name']
                        result.append(temp)
                        switch = True
        return {'members': list(result)}, next_token

    def add_principals(self, principals: List[Type['Principal']], access_level: str):
        """
        add a typed link from resource to principal with the access type.
        verifies that the policy exists before making link

        :param principal_type:
        :param name:
        :param access_level:
        :return:
        """
        # Check policy exists
        self.resource_type.policy_exists(access_level)
        p = defaultdict(list)
        for principal in principals:
            p[principal.object_type].append(principal)
        operations = []
        for object_type, links in p.items():
            operations.extend(self._add_typed_links_batch(
                links,
                'access_link',
                {'access_level': access_level,
                 'resource': self.resource_type.name,
                 'principal': object_type},
                incoming=True))
        self.cd.batch_write(operations)
        self._principals = None  # update roles
        logger.info(dict(message="Changed resource access permission for principals.",
                         resource=dict(type=self.object_type, path_name=self._path_name),
                         principals=p,
                         access_level=access_level
                         ))

    def remove_principals(self, principals: List[Type['Principal']]):
        p = defaultdict(list)
        for principal in principals:
            p[principal.object_type].append(principal)
        operations = []
        for object_type, links in p.items():
            operations.extend(self._remove_typed_links_batch(
                links,
                'access_link',
                {'resource': self.resource_type.name,
                 'principal': object_type},
                incoming=True))
        self.cd.batch_write(operations)
        self._principals = None  # update roles
        logger.info(dict(message="Removed resource access permission for principals.",
                         resource=dict(type=self.object_type, path_name=self._path_name),
                         principals=p,
                         ))

    def update_principal(self, principal: Type['Principal'], access_level: str):
        tls = self.cd.make_typed_link_specifier(
            principal.object_ref,
            self.object_ref,
            'access_link',
            {'principal': principal.object_type,
             'resource': self.resource_type.name})
        uop = [UpdateObjectParams('access_link',
                                  'access_level',
                                  ValueTypes.StringValue,
                                  access_level,
                                  UpdateActions.CREATE_OR_UPDATE,
                                  )]
        self.cd.update_link_attributes(tls, uop)

    def delete_node(self):
        try:
            self.cd.delete_object(self.object_ref, delete_children=True)
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeNotFoundException(f"Failed to delete {self.name}. {self.object_type} does not exist.")

    def modify_principals(self, principals: List[Dict[str, str]]) -> None:
        """
        Modify a list of principals to grant them access to this resource id by adding, updating or deleting access
        levels as needed.

        :param principals: list of principals to grant access to this resource id
        :return:
        """
        ops = []
        modifications = []
        for p in principals:
            principal = User(p['member']) if p['member_type'] == 'user' else Group(p['member'])
            modifications.append((principal, p.get('access_level')))
            # tls is a pointer to the edge connecting a principal and resource.
            tls = self.cd.make_typed_link_specifier(
                principal.object_ref,
                self.object_ref,
                'access_link',
                {'principal': principal.object_type,
                 'resource': self.resource_type.name})
            ops.append(self.cd.batch_get_link_attributes(tls, ['access_level']))

        try:
            for modifications, r in zip(modifications, self.cd.batch_read(ops)['Responses']):
                if r.get('SuccessfulResponse'):
                    current_ap = r['SuccessfulResponse']['GetLinkAttributes']['Attributes'][0]['Value'].popitem()[1]
                    if modifications[1] == current_ap:  # Pass
                        # If the old access level of the principal is equal to the new access level, then do nothing.
                        continue
                    elif modifications[1] is None:  # delete
                        # If the access level field is missing, then remove access for the principal
                        self.remove_principals([modifications[0]])
                    elif modifications[1] != current_ap:  # update
                        # If the new access level is not equal to the old access level then we update it to match.
                        self.update_principal(*modifications)
                else:
                    # If the principal had no previous access level, then create a new access level edge in cloud
                    # directory between the principal and the resource id
                    self.add_principals([modifications[0]], modifications[1])

        except cd_client.exceptions.ResourceNotFoundException:
            return None

    def check_access(self, principals: List[Type['Principal']]) -> Union[None, List[str]]:
        """
        Given a list of principals, return a list of access levels to this resource id for each principal

        :param principals:
        :return: list of access levels to this resource id, one for each principal
        """
        ops = []
        for principal in principals:
            tls = self.cd.make_typed_link_specifier(
                principal.object_ref,
                self.object_ref,
                'access_link',
                {'principal': principal.object_type,
                 'resource': self.resource_type.name})
            ops.append(self.cd.batch_get_link_attributes(tls, ['access_level']))
        try:
            attributes = [r['SuccessfulResponse']['GetLinkAttributes']['Attributes'] for r in self.cd.batch_read(ops)[
                'Responses'] if r.get('SuccessfulResponse')]
        except cd_client.exceptions.ResourceNotFoundException:
            return None
        else:
            access_levels = set()
            for attr in attributes:
                access_levels.add(self.resource_type.get_policy_path(attr[0]['Value'].popitem()[1]))
            return list(access_levels)

    def get_resource_policy(self, principals: List[Type['Principal']]):
        resource_policy = self.check_access(principals)
        return self.cd.get_policies(resource_policy)
