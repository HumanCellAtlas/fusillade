import json
import os
from typing import List, Dict, Any, Union

from fusillade.clouddirectory import CloudNode, cd_client, ConsistencyLevel, logger
from fusillade.errors import FusilladeHTTPException, FusilladeBadRequestException
from fusillade.policy.validator import verify_iam_policy

proj_path = os.path.dirname(__file__)
default_resource_owner_policy = os.path.join(proj_path, '..', 'policies', 'default_resource_owner_policy.json')


class ResourceType(CloudNode):
    _attributes = ['actions'] + CloudNode._attributes
    _facet: str = 'NodeFacet'
    object_type: str = 'resource'
    _default_policy_path: str = default_resource_owner_policy
    policy_type = 'Resource'

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
            new_node.cd.get_obj_type_path(cls.object_type),
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
        # link owner to resource
        if not owner_policy and not getattr(cls, '_default_policy_path', None):
            raise FusilladeHTTPException('Must provide owner policy.')
        else:
            if owner_policy:
                owner_policy = new_node.format_policy(owner_policy)
                verify_iam_policy(owner_policy)
            elif getattr(cls, '_default_policy_path'):
                with open(cls._default_policy_path, 'r') as fp:
                    owner_policy = json.load(fp)
            ops.extend(new_node.create_policy('Owner',
                                              owner_policy,
                                              parent_path='#policy_node',
                                              run=False,
                                              type=new_node.object_type,
                                              name=f"{new_node.name}:Owner"))

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

    # TODO: Add function to modify actions, this will need to modify all access policies with this actions
    @property
    def actions(self):
        if not self._actions:
            self._get_attributes(self._attributes)
        if isinstance(self._actions, str):
            self._actions = self._actions.split(' ')
        return self._actions

    def add_actions(self):
        set(self._actions)

    def check_actions(self, policy: dict):
        policy_actions = set()
        for s in policy['Statement']:
            policy_actions.update(s['Action'])
        if not policy_actions.issubset(set(self.actions)):
            raise FusilladeBadRequestException(detail="Invalid actions in policy.")

    @staticmethod
    def hash_name(name):
        return name

    def list_policies(self, per_page=None, next=None):
        children, next_token = self.cd.list_object_children_paged(f"{self.object_ref}/policy", next, per_page)
        return [f"/resource/{self.name}/policy/{child}" for child in children.keys()], next_token

    @staticmethod
    def format_policy(policy: dict) -> str:
        policy.update(Version="2012-10-17")
        return json.dumps(policy)

    def create_policy(self,
                      policy_name: str,
                      policy: dict,
                      policy_type: str = 'IAMPolicy',
                      parent_path: str = None,
                      run=True,
                      **kwargs) -> Union[None, List[Dict[str,Any]]]:
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
        operations = list()
        object_attribute_list = self.cd.get_policy_attribute_list(policy_type, self.format_policy(policy), **kwargs)
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
