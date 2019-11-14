"""
clouddrectory.py

This modules is used to simplify access to AWS Cloud Directory. For more information on AWS Cloud Directory see
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/clouddirectory.html

"""
import functools
import hashlib
import json
import logging
import os
from collections import namedtuple, defaultdict
from datetime import datetime
from enum import Enum, auto
from typing import Iterator, Any, Tuple, Dict, List, Callable, Optional, Union, Type, Set

import itertools

from dcplib.aws import clients as aws_clients
from fusillade import Config
from fusillade.config import proj_path
from fusillade.errors import FusilladeException, FusilladeHTTPException, FusilladeNotFoundException, \
    AuthorizationException, FusilladeLimitException, FusilladeBadRequestException
from fusillade.policy.validator import verify_policy
from fusillade.utils.retry import retry

logger = logging.getLogger(__name__)

cd_client = aws_clients.clouddirectory
project_arn = "arn:aws:clouddirectory:{}:{}:".format(
    os.getenv('AWS_DEFAULT_REGION'),
    aws_clients.sts.get_caller_identity().get('Account'))

# TODO make all configurable
directory_schema_path = os.path.join(proj_path, 'directory_schema.json')
default_user_policy_path = os.path.join(proj_path, '..', 'policies', 'default_user_policy.json')
default_group_policy_path = os.path.join(proj_path, '..', 'policies', 'default_group_policy.json')
default_admin_role_path = os.path.join(proj_path, '..', 'policies', 'default_admin_role.json')
default_user_role_path = os.path.join(proj_path, '..', 'policies', 'default_user_role.json')
default_role_path = os.path.join(proj_path, '..', 'policies', 'default_role.json')

cd_read_retry_parameters = dict(timeout=5,
                                delay=0.1,
                                retryable=lambda e: isinstance(e, cd_client.exceptions.RetryableConflictException))

cd_write_retry_parameters = dict(timeout=5,
                                 delay=0.2,
                                 retryable=lambda e: isinstance(e, cd_client.exceptions.RetryableConflictException))


def get_json_file(file_name) -> Dict[str, Any]:
    with open(file_name, 'r') as fp:
        return json.load(fp)


def get_published_schema_from_directory(dir_arn: str) -> str:
    schema = cd_client.list_applied_schema_arns(DirectoryArn=dir_arn)['SchemaArns'][0]
    schema = schema.split('/')[-2:]
    schema = '/'.join(schema)
    return f"{project_arn}schema/published/{schema}"


def cleanup_directory(dir_arn: str):
    cd_client.disable_directory(DirectoryArn=dir_arn)
    cd_client.delete_directory(DirectoryArn=dir_arn)
    logger.warning({"message": "Deleted directory", "directory_arn": dir_arn})


def cleanup_schema(sch_arn: str) -> None:
    cd_client.delete_schema(SchemaArn=sch_arn)
    logger.warning({"message": "Deleted schema", "schema_arn": sch_arn})


def publish_schema(name: str, Version: str, MinorVersion: str = '0') -> str:
    """
    More info about schemas
    https://docs.aws.amazon.com/clouddirectory/latest/developerguide/schemas.html
    """
    # don't create if already created
    try:
        dev_schema_arn = cd_client.create_schema(Name=name)['SchemaArn']
        logger.info({"message": "Created development schema", "developement_schema_arn": dev_schema_arn})
    except cd_client.exceptions.SchemaAlreadyExistsException:
        dev_schema_arn = f"{project_arn}schema/development/{name}"

    # update the schema
    with open(directory_schema_path) as fp:
        schema = fp.read()
    cd_client.put_schema_from_json(SchemaArn=dev_schema_arn, Document=schema)
    try:
        pub_schema_arn = cd_client.publish_schema(DevelopmentSchemaArn=dev_schema_arn,
                                                  Version=Version,
                                                  MinorVersion=MinorVersion)['PublishedSchemaArn']
        logger.info({"message": "Published development schema",
                     "developement_schema_arn": dev_schema_arn,
                     "published_schema_arn": pub_schema_arn})
    except cd_client.exceptions.SchemaAlreadyPublishedException:
        pub_schema_arn = f"{project_arn}schema/published/{name}/{Version}/{MinorVersion}"
    return pub_schema_arn


def create_directory(name: str, schema: str, admins: List[str]) -> 'CloudDirectory':
    """
    Retrieve the fusillade cloud directory or do a one time setup of cloud directory to be used with fusillade.

    :param name:
    :param schema:
    :param admins: a list of admins to create
    :return:
    """
    directory = None
    try:
        response = cd_client.create_directory(
            Name=name,
            SchemaArn=schema
        )
        directory = CloudDirectory(response['DirectoryArn'])
        logger.info({"message": "Created new directory", "directory_arn": directory._dir_arn})
    except cd_client.exceptions.DirectoryAlreadyExistsException:
        directory = CloudDirectory.from_name(name)
    else:
        # create structure
        for folder_name in obj_type_path.keys():
            directory.create_folder('/', folder_name)

        # create roles
        Role.create("default_user", statement=get_json_file(default_user_role_path))
        Role.create("fusillade_admin", statement=get_json_file(default_admin_role_path))
        Group.create("user_default").add_roles(['default_user'])

        # create admins
        for admin in admins:
            User.provision_user(admin, roles=['fusillade_admin'])
        User.provision_user('public')
        logger.info({"message": "Created New Directory",
                     "schema_arn": schema,
                     "directory_name": name,
                     "admins": admins})
    cd_client.tag_resource(
        ResourceArn=directory._dir_arn,
        Tags=[
            {'Key': 'project', "Value": os.getenv("FUS_PROJECT_TAG", '')},
            {'Key': 'owner', "Value": os.getenv("FUS_OWNER_TAG", '')},
            {'Key': 'env', "Value": os.getenv("FUS_DEPLOYMENT_STAGE")},
            {'Key': 'Name', "Value": "fusillade-directory"},
            {'Key': 'managedBy', "Value": "manual"}
        ]
    )
    verify_directory(directory)
    return directory


def verify_directory(directory: 'CloudDirectory'):
    """Checks that the directory has the correct paths setup. This is for upgrading existing directories if needed."""
    for folder_name in obj_type_path.keys():
        try:
            directory.get_object_information(f"/{folder_name}")
        except cd_client.exceptions.ResourceNotFoundException:
            directory.create_folder('/', folder_name)


def clear_cd(directory: 'CloudDirectory',
             users: List[str] = None,
             groups: List[str] = None,
             roles: List[str] = None) -> None:
    """

    :param users: a list of users to keep
    :param groups: a list of groups to keep
    :param roles: a list of roles to keep
    :return:
    """
    users = users if users else []
    groups = groups if groups else []
    roles = roles if roles else []
    protected_users = [User.hash_name(name) for name in ['public'] + users]
    protected_groups = [Group.hash_name(name) for name in ['user_default'] + groups]
    protected_roles = [Role.hash_name(name) for name in ["fusillade_admin", "default_user"] + roles]

    for name, obj_ref in directory.list_object_children('/user/', ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name):
        if name not in protected_users:
            directory.delete_object(obj_ref)
    for name, obj_ref in directory.list_object_children('/group/', ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name):
        if name not in protected_groups:
            directory.delete_object(obj_ref)
    for name, obj_ref in directory.list_object_children('/role/', ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name):
        if name not in protected_roles:
            directory.delete_object(obj_ref)
    for name, obj_ref in directory.list_object_children('/resource/',
                                                        ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name):
        directory.delete_object(obj_ref, delete_children=True)


@retry(**cd_read_retry_parameters, inherit=True)
def _paging_loop(fn: Callable, key: str, upack_response: Optional[Callable] = None, **kwarg):
    while True:
        resp = fn(**kwarg)
        for i in resp[key]:
            yield i if not upack_response else upack_response(i)
        kwarg['NextToken'] = resp.get("NextToken")
        if not kwarg['NextToken']:
            break


def list_directories(state: str = 'ENABLED') -> Iterator:
    return _paging_loop(cd_client.list_directories, 'Directories', state=state)


class UpdateActions(Enum):
    CREATE_OR_UPDATE = auto()
    DELETE = auto()


obj_type_path = dict(
    group='/group/',
    index='/index/',
    user='/user/',
    policy='/policy/',
    role='/role/',
    resource='/resource/'
)


class ValueTypes(Enum):
    StringValue = auto()
    BinaryValue = auto()
    BooleanValue = auto()
    NumberValue = auto()
    DatetimeValue = auto()


class ConsistencyLevel(Enum):
    """
    Use by clouddirectory for read and write function to control the consistency of responses from the directory.
    See https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_consistency_levels.html
    """
    SERIALIZABLE = auto()
    EVENTUAL = auto()


class UpdateObjectParams(namedtuple("UpdateObjectParams", ['facet', 'attribute', 'value_type', 'value', 'action'])):
    pass


def batch_reference(func):
    def wrapper(*args, **kwargs):
        """
        If batch_reference is a kwarg, it is added to the batch request as BatchReference. Batch referencing simplifies
        the process of referencing objects in another batch request.
        """
        batch_ref = kwargs.pop('batch_reference', None)
        r = func(*args, **kwargs)
        if batch_ref:
            for key in r.keys():
                r[key]['BatchReferenceName'] = batch_ref
        return r

    return wrapper


class CloudDirectory:
    _page_limit = 30  # This is the max allowed by AWS
    _batch_write_max = 20  # This is the max allowed by AWS
    _lookup_policy_max = 3  # Max recommended by AWS Support

    def __init__(self, directory_arn: str):
        self._dir_arn = directory_arn
        self._schema = None
        # This is the custom schema applied to the cloud directory. It is defined in fusillade/directory_schema.json.
        self.node_schema = f"{self._dir_arn}/schema/CloudDirectory/1.0"
        # This is the base schema that is always present in AWS Cloud Directory. It defines the basic Node types, NODE,
        # POLICY, LEAF_NODE, and INDEX.

    @classmethod
    @functools.lru_cache()
    def from_name(cls, dir_name: str) -> 'CloudDirectory':
        # get directory arn by name
        for i in list_directories():
            if i['Name'] == dir_name:
                dir_arn = i['DirectoryArn']
                return cls(dir_arn)
        raise FusilladeException(f"{dir_name} does not exist")

    @property
    def schema(self):
        if not self._schema:
            self._schema = cd_client.list_applied_schema_arns(DirectoryArn=self._dir_arn)['SchemaArns'][0]
        return self._schema

    @retry(**cd_read_retry_parameters)
    def list_object_children_paged(self, object_ref: str,
                                   next_token: Optional[str] = None,
                                   per_page=None, **kwargs) -> Tuple[dict, Optional[str]]:
        """
        a wrapper around CloudDirectory.Client.list_object_children with paging

        :param object_ref:
        :param next_token:
        :param per_page:
        :return:
        """
        kwargs.update(
            DirectoryArn=self._dir_arn,
            ObjectReference={'Selector': object_ref},
            MaxResults=min(per_page, self._page_limit) if per_page else self._page_limit,
        )
        if next_token:
            kwargs['NextToken'] = next_token
        result = cd_client.list_object_children(**kwargs)
        return result['Children'], result.get("NextToken")

    @retry(**cd_read_retry_parameters)
    def list_object_children(self, object_ref: str, **kwargs) -> Iterator[Tuple[str, str]]:
        """
        a wrapper around CloudDirectory.Client.list_object_children
        """
        resp = cd_client.list_object_children(DirectoryArn=self._dir_arn,
                                              ObjectReference={'Selector': object_ref},
                                              MaxResults=self._page_limit,
                                              **kwargs)
        while True:
            for name, ref in resp['Children'].items():
                yield name, '$' + ref
            next_token = resp.get('NextToken')
            if next_token:
                resp = cd_client.list_object_children(DirectoryArn=self._dir_arn,
                                                      ObjectReference={'Selector': object_ref},
                                                      NextToken=next_token,
                                                      MaxResults=self._page_limit)
            else:
                break

    def list_object_parents(self,
                            object_ref: str,
                            include_all_links_to_each_parent: bool = True,
                            **kwargs) -> Iterator:
        """
        a wrapper around CloudDirectory.Client.list_object_parents with paging
        """
        if include_all_links_to_each_parent:
            def unpack_response(i):
                return '$' + i['ObjectIdentifier'], i['LinkName']

            return _paging_loop(cd_client.list_object_parents,
                                'ParentLinks',
                                unpack_response,
                                DirectoryArn=self._dir_arn,
                                ObjectReference={'Selector': object_ref},
                                IncludeAllLinksToEachParent=include_all_links_to_each_parent,
                                MaxResults=self._page_limit,
                                **kwargs
                                )
        else:
            return _paging_loop(cd_client.list_object_parents,
                                'Parents',
                                self._make_ref,
                                DirectoryArn=self._dir_arn,
                                ObjectReference={'Selector': object_ref},
                                IncludeAllLinksToEachParent=include_all_links_to_each_parent,
                                MaxResults=self._page_limit,
                                **kwargs
                                )

    def list_object_policies(self, object_ref: str, **kwargs) -> Iterator[str]:
        """
        a wrapper around CloudDirectory.Client.list_object_policies with paging
        """
        return _paging_loop(cd_client.list_object_policies,
                            'AttachedPolicyIds',
                            self._make_ref,
                            DirectoryArn=self._dir_arn,
                            ObjectReference={'Selector': object_ref},
                            MaxResults=self._page_limit,
                            **kwargs
                            )

    def list_policy_attachments(self, policy: str, **kwargs) -> Iterator[str]:
        """
        a wrapper around CloudDirectory.Client.list_policy_attachments with paging
        """
        return _paging_loop(cd_client.list_policy_attachments,
                            'ObjectIdentifiers',
                            self._make_ref,
                            DirectoryArn=self._dir_arn,
                            PolicyReference={'Selector': policy},
                            MaxResults=self._page_limit,
                            **kwargs
                            )

    def list_object_parent_paths(self, object_ref: str, **kwargs) -> Iterator[str]:
        return _paging_loop(cd_client.list_object_parent_paths,
                            'PathToObjectIdentifiersList',
                            DirectoryArn=self._dir_arn,
                            ObjectReference={'Selector': object_ref},
                            MaxResults=self._page_limit,
                            **kwargs
                            )

    @retry(**cd_read_retry_parameters)
    def _list_typed_links(self,
                          func: Callable,
                          key: str,
                          object_ref: str,
                          filter_attribute_ranges: Optional[List],
                          filter_typed_link: Optional[str],
                          paged=False,
                          per_page=None,
                          next_token=None,
                          **kwargs) -> Union[Iterator[dict], Tuple[List[Dict], str]]:
        kwargs.update(dict(
            DirectoryArn=self._dir_arn,
            ObjectReference={'Selector': object_ref},
            MaxResults=min(per_page, self._page_limit) if per_page else self._page_limit
        ))
        if filter_attribute_ranges:
            kwargs['FilterAttributeRanges'] = filter_attribute_ranges
        if filter_typed_link:
            kwargs['FilterTypedLink'] = {
                'SchemaArn': self.schema,
                'TypedLinkName': filter_typed_link
            }
        if next_token:
            kwargs["NextToken"] = next_token
        if paged:
            resp = func(**kwargs)
            return list(resp[key]), resp.get("NextToken")
        else:
            return _paging_loop(func, key, **kwargs)

    def list_outgoing_typed_links(self,
                                  object_ref: str,
                                  filter_attribute_ranges: List = None,
                                  filter_typed_link: str = None,
                                  **kwargs) -> Iterator[dict]:
        """
        a wrapper around CloudDirectory.Client.list_outgoing_typed_links

        :return: typed link specifier generator
        """
        return self._list_typed_links(cd_client.list_outgoing_typed_links,
                                      'TypedLinkSpecifiers',
                                      object_ref,
                                      filter_attribute_ranges,
                                      filter_typed_link,
                                      **kwargs)

    def list_incoming_typed_links(
            self,
            object_ref: str,
            filter_attribute_ranges: List = None,
            filter_typed_link: str = None,
            **kwargs) -> Iterator[dict]:
        """
        a wrapper around CloudDirectory.Client.list_incoming_typed_links

        :return: typed link specifier generator
        """
        return self._list_typed_links(
            cd_client.list_incoming_typed_links,
            'LinkSpecifiers',
            object_ref,
            filter_attribute_ranges,
            filter_typed_link,
            **kwargs)

    @staticmethod
    def _make_ref(i):
        return i if i[0] == '$' else '$' + i

    @retry(**cd_read_retry_parameters)
    def get_object_attributes(self, obj_ref: str, facet: str, attributes: List[str],
                              schema=None) -> Dict[str, Any]:
        """
        a wrapper around CloudDirectory.Client.get_object_attributes
        """
        if not schema:
            schema = self.schema
        return cd_client.get_object_attributes(DirectoryArn=self._dir_arn,
                                               ObjectReference={'Selector': obj_ref},
                                               SchemaFacet={
                                                   'SchemaArn': schema,
                                                   'FacetName': facet
                                               },
                                               AttributeNames=attributes,
                                               ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name
                                               )

    def get_object_attribute_list(self, facet="LeafFacet", **kwargs) -> List[Dict[str, Any]]:
        return [dict(Key=dict(SchemaArn=self.schema, FacetName=facet, Name=k), Value=dict(StringValue=v))
                for k, v in kwargs.items()]

    def get_policy_attribute_list(self,
                                  policy_type: str,
                                  statement: Dict[str, Any],
                                  **kwargs) -> List[Dict[str, Any]]:
        """
        policy_type and policy_document are required field for a policy object. See the section on Policies for more
        info https://docs.aws.amazon.com/clouddirectory/latest/developerguide/key_concepts_directory.html
        """
        attributes = self.get_object_attribute_list(facet='IAMPolicy', **kwargs)
        statement.update(Version="2012-10-17")
        attributes.extend([
            dict(
                Key=dict(
                    SchemaArn=self.node_schema,
                    FacetName='POLICY',
                    Name='policy_type'),
                Value=dict(
                    StringValue=policy_type)),
            dict(
                Key=dict(
                    SchemaArn=self.node_schema,
                    FacetName='POLICY',
                    Name="policy_document"),
                Value=dict(
                    BinaryValue=json.dumps(statement).encode()))
        ])
        return attributes

    def update_object_attribute(self,
                                object_ref: str,
                                update_params: List[UpdateObjectParams],
                                schema=None) -> Dict[str, Any]:
        """
        a wrapper around CloudDirectory.Client.update_object_attributes

        :param object_ref: The reference that identifies the object.
        :param update_params: a list of attributes to modify.
        :param schema:
        :return:
        """
        if not schema:
            schema = self.schema
        updates = [
            {
                'ObjectAttributeKey': {
                    'SchemaArn': schema,
                    'FacetName': i.facet,
                    'Name': i.attribute
                },
                'ObjectAttributeAction': {
                    'ObjectAttributeActionType': i.action.name,
                    'ObjectAttributeUpdateValue': {
                        i.value_type.name: i.value
                    }
                }
            } for i in update_params]
        return cd_client.update_object_attributes(
            DirectoryArn=self._dir_arn,
            ObjectReference={
                'Selector': object_ref
            },
            AttributeUpdates=updates
        )

    def update_link_attributes(self, tls,
                               update_params: List[UpdateObjectParams],
                               schema=None) -> Dict[str, Any]:
        """
        a wrapper around CloudDirectory.Client.update_object_attributes

        :param object_ref: The reference that identifies the object.
        :param update_params: a list of attributes to modify.
        :param schema:
        :return:
        """
        if not schema:
            schema = self.schema
        updates = [
            {
                'AttributeKey': {
                    'SchemaArn': schema,
                    'FacetName': i.facet,
                    'Name': i.attribute
                },
                'AttributeAction': {
                    'AttributeActionType': i.action.name,
                    'AttributeUpdateValue': {
                        i.value_type.name: i.value
                    }
                }
            } for i in update_params]
        return cd_client.update_link_attributes(
            DirectoryArn=self._dir_arn,
            TypedLinkSpecifier=tls,
            AttributeUpdates=updates
        )

    def create_folder(self, path: str, name: str, created_by: str = "fusillade") -> None:
        """ A folder is just a NodeFacet"""
        schema_facets = [dict(SchemaArn=self.schema, FacetName="NodeFacet")]
        object_attribute_list = self.get_object_attribute_list(facet="NodeFacet", name=name, created_by=created_by)
        try:
            cd_client.create_object(DirectoryArn=self._dir_arn,
                                    SchemaFacets=schema_facets,
                                    ObjectAttributeList=object_attribute_list,
                                    ParentReference=dict(Selector=path),
                                    LinkName=name)
            logger.info({"message": "creating folder", "name": name, "path": path})
        except cd_client.exceptions.LinkNameAlreadyInUseException:
            pass

    @retry(cd_write_retry_parameters)
    def attach_typed_link(
            self,
            source: str,
            target: str,
            typed_link_facet: str,
            attributes: Dict[str, Any]):
        """
        a wrapper around CloudDirectory.Client.attach_typed_link
        """
        return cd_client.attach_typed_link(
            DirectoryArn=self._dir_arn,
            SourceObjectReference={
                'Selector': source
            },
            TargetObjectReference={
                'Selector': target
            },
            TypedLinkFacet={
                'SchemaArn': self.schema,
                'TypedLinkName': typed_link_facet
            },
            Attributes=self.make_attributes(attributes)
        )

    @retry(cd_write_retry_parameters)
    def detach_typed_link(self, typed_link_specifier: Dict[str, Any]):
        """
        a wrapper around CloudDirectory.Client.detach_typed_link

        :param typed_link_specifier: identifies the typed link to remove
        :return:
        """
        return cd_client.detach_typed_link(
            DirectoryArn=self._dir_arn,
            TypedLinkSpecifier=typed_link_specifier
        )

    @staticmethod
    def make_attributes(kwargs: Dict[str, Any]) -> List:
        """
        A helper function used to create
        :param kwargs:
        :return:
        """

        def _make_attribute(name: str, value: any):
            attribute = {'AttributeName': name}
            if isinstance(value, str):
                attribute['Value'] = {ValueTypes.StringValue.name: value}
            elif isinstance(value, bytes):
                attribute['Value'] = {ValueTypes.BinaryValue.name: value}
            elif isinstance(value, bool):
                attribute['Value'] = {ValueTypes.BooleanValue.name: value}
            elif isinstance(value, int):
                attribute['Value'] = {ValueTypes.NumberValue.name: str(value)}
                #  int to str is required by cloud directory
            elif isinstance(value, datetime):
                attribute['Value'] = {ValueTypes.DatetimeValue.name: value}
            else:
                raise ValueError()
            return attribute

        return [_make_attribute(name, value) for name, value in kwargs.items()]

    def make_typed_link_specifier(
            self,
            source_object_ref: str,
            target_object_ref: str,
            typed_link_facet_name: str,
            attributes: Dict[str, Any]):
        return {
            'SourceObjectReference': {
                'Selector': source_object_ref
            },
            'TargetObjectReference': {
                'Selector': target_object_ref
            },
            'TypedLinkFacet': {
                'SchemaArn': self.schema,
                'TypedLinkName': typed_link_facet_name
            },
            'IdentityAttributeValues': self.make_attributes(attributes)
        }

    def delete_policy(self, policy_ref: str) -> None:
        """
        See details on deletion requirements for more info
        https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html
        """
        self.batch_write(
            [self.batch_detach_policy(policy_ref, obj_ref) for obj_ref in self.list_policy_attachments(
                policy_ref,
                ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name)])
        self.batch_write(
            [self.batch_detach_object(parent_ref, link_name) for parent_ref, link_name in self.list_object_parents(
                policy_ref,
                ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name)])
        retry(**cd_read_retry_parameters)(cd_client.delete_object)(
            DirectoryArn=self._dir_arn,
            ObjectReference={'Selector': policy_ref})

    def delete_object(self, obj_ref: str, delete_children=False) -> None:
        """
        See details on deletion requirements for more info
        https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html

        if delete_children is true all children of the object will be deleted
        """
        object_id = f"${self.get_object_information(obj_ref)['ObjectIdentifier']}"
        params = dict(object_ref=object_id, ConsistencyLevel=ConsistencyLevel.SERIALIZABLE.name)
        [self.delete_policy(policy_ref) for policy_ref in self.list_object_policies(**params)]
        self.batch_write([
            self.batch_detach_object(parent_ref, link_name)
            for parent_ref, link_name in
            self.list_object_parents(**params)], allowed_errors=['ResourceNotFoundException'])
        self.batch_write([
            self.batch_detach_typed_link(i)
            for i in
            self.list_incoming_typed_links(**params)], allowed_errors=['ResourceNotFoundException'])
        self.batch_write([
            self.batch_detach_typed_link(i)
            for i in
            self.list_outgoing_typed_links(**params)], allowed_errors=['ResourceNotFoundException'])
        try:
            links = []
            children = []
            for link_name, child_ref in self.list_object_children(**params):
                links.append(link_name)
                children.append(child_ref)
            self.batch_write([self.batch_detach_object(object_id, link) for link in links],
                             allowed_errors=['ResourceNotFoundException'])
            if delete_children:
                for child in children:
                    self.delete_object(child, delete_children=delete_children)
        except cd_client.exceptions.NotNodeException:
            pass
        retry(**cd_read_retry_parameters)(cd_client.delete_object)(
            DirectoryArn=self._dir_arn,
            ObjectReference={'Selector': object_id})

    @staticmethod
    @batch_reference
    def batch_detach_policy(policy_ref: str, object_ref: str) -> Dict[str, Any]:
        """
        A helper function to format a batch detach_policy operation
        """
        return {
            'DetachPolicy': {
                'PolicyReference': {'Selector': policy_ref},
                'ObjectReference': {'Selector': object_ref}
            }
        }

    @batch_reference
    def batch_create_object(self,
                            parent: str,
                            link_name: str,
                            facet_name: str,
                            object_attribute_list: List[Dict[str, Any]],
                            ) -> Dict[str, Any]:
        """
        A helper function to format a batch create_object operation
        """
        return {
            'CreateObject': {
                'SchemaFacet': [
                    {
                        'SchemaArn': self.schema,
                        'FacetName': facet_name
                    },
                ],
                'ObjectAttributeList': object_attribute_list,
                'ParentReference': {
                    'Selector': parent
                },
                'LinkName': link_name,
            }
        }

    @batch_reference
    def batch_get_attributes(self, obj_ref, facet, attributes: List[str], schema=None) -> Dict[str, Any]:
        """
        A helper function to format a batch get_attributes operation
        """
        return {
            'GetObjectAttributes': {
                'ObjectReference': {
                    'Selector': obj_ref
                },
                'SchemaFacet': {
                    'SchemaArn': schema if schema else self.schema,
                    'FacetName': facet
                },
                'AttributeNames': attributes
            }
        }

    @staticmethod
    @batch_reference
    def batch_attach_object(parent: str, child: str, name: str) -> Dict[str, Any]:
        """
        A helper function to format a batch attach_object operation
        """
        return {
            'AttachObject': {
                'ParentReference': {
                    'Selector': parent
                },
                'ChildReference': {
                    'Selector': child
                },
                'LinkName': name
            }
        }

    @staticmethod
    @batch_reference
    def batch_detach_object(parent: str, link_name: str) -> Dict[str, Any]:
        """
        A helper function to format a batch detach_object operation
        """
        return {'DetachObject': {
            'ParentReference': {
                'Selector': parent
            },
            'LinkName': link_name,
        }}

    @staticmethod
    @batch_reference
    def batch_attach_policy(policy: str, object_ref: str) -> Dict[str, Any]:
        """
        A helper function to format a batch attach_policy operation
        """
        return {
            'AttachPolicy': {
                'PolicyReference': {
                    'Selector': policy
                },
                'ObjectReference': {
                    'Selector': object_ref
                }
            }
        }

    @batch_reference
    def batch_attach_typed_link(self,
                                parent: str,
                                child: str,
                                facet_name: str,
                                attributes: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'AttachTypedLink': {
                'SourceObjectReference': {
                    'Selector': parent
                },
                'TargetObjectReference': {
                    'Selector': child
                },
                'TypedLinkFacet': {
                    'SchemaArn': self.schema,
                    'TypedLinkName': facet_name
                },
                'Attributes': self.make_attributes(attributes)
            }
        }

    @staticmethod
    @batch_reference
    def batch_detach_typed_link(typed_link_specifier) -> Dict[str, Any]:
        return {
            'DetachTypedLink': {
                'TypedLinkSpecifier': typed_link_specifier
            },
        }

    @batch_reference
    def batch_lookup_policy(self, obj_ref: str, next_token: str = None) -> Dict[str, Any]:
        temp = {
            'ObjectReference': {
                'Selector': obj_ref
            },
            'MaxResults': self._lookup_policy_max
        }
        if next_token:
            temp['NextToken'] = next_token
        return {'LookupPolicy': temp}

    @batch_reference
    def batch_get_object_info(self, obj_ref: str):
        return {
            'GetObjectInformation': {
                'ObjectReference': {
                    'Selector': obj_ref
                }
            }
        }

    @retry(**cd_write_retry_parameters)
    def batch_write(self, operations: list, allowed_errors: List[str] = None) -> List[dict]:
        """
        A wrapper around CloudDirectory.Client.batch_write
        """
        allowed_errors = allowed_errors or []
        responses = []  # contains succesful responses
        while True:
            try:
                for i in range(0, len(operations), self._batch_write_max):
                    ops = operations[i:i + self._batch_write_max]
                    responses.extend(
                        cd_client.batch_write(
                            DirectoryArn=self._dir_arn,
                            Operations=ops)['Responses'])
                break
            except cd_client.exceptions.BatchWriteException as ex:
                parsed_msg = ex.response['Error']['Message'].split(" ")
                failed_op_index, error = (int(parsed_msg[1]), parsed_msg[2])
                logger.warning({
                    "message": ex,
                    "response": ex.response,
                    "operations": {
                        "failed": operations.pop(i + failed_op_index),
                        "skipped": len(operations[i:]),
                        "sucessful": len(operations[:i + failed_op_index])
                    }
                })
                if error[:-1] in allowed_errors:
                    operations = operations[i:]
                else:
                    raise ex

        return responses

    @retry(**cd_read_retry_parameters)
    def batch_read(self, operations: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """
        A wrapper around CloudDirectory.Client.batch_read
        """
        return cd_client.batch_read(DirectoryArn=self._dir_arn, Operations=operations, **kwargs)

    @staticmethod
    def get_obj_type_path(obj_type: str) -> str:
        obj_type = obj_type.lower()
        try:
            return obj_type_path[obj_type]
        except KeyError:
            if obj_type.startswith('resource'):
                # check that it's a resource type with format resource/resource_type
                return f'/{obj_type}/id/'

    def lookup_policy(self, object_id: str) -> List[Dict[str, Any]]:
        # retrieve all of the policies attached to an object and its parents.
        policies_paths = [
            path
            for response in cd_client.get_paginator('lookup_policy').paginate(
                DirectoryArn=self._dir_arn,
                ObjectReference={'Selector': object_id},
                PaginationConfig={'PageSize': self._lookup_policy_max}
            )
            for path in response['PolicyToPathList']
        ]
        return policies_paths

    @retry(**cd_read_retry_parameters)
    def get_link_attributes(self, TypedLinkSpecifier, AttributeNames, **kwargs) -> Dict[str, str]:
        resp = cd_client.get_link_attributes(
            DirectoryArn=self._dir_arn,
            TypedLinkSpecifier=TypedLinkSpecifier,
            AttributeNames=AttributeNames,
            **kwargs
        )
        attributes = dict()
        for attr in resp['Attributes']:
            attributes[attr['Key']['Name']] = attr['Value'].popitem()[1]
        return attributes

    def get_policies(self,
                     policy_paths: List[Dict[str, Any]],
                     policy_type='IAMPolicy') -> Dict[str, Union[List[Dict[str, str]], List[str]]]:
        """
        Get's policy statements and attributes.

        :param policy_paths: a list of paths leading to policy nodes stored in cloud directory
        :param policy_type: the type of policies to retrieve from the policy nodes
        :return: returns the policies of the type IAMPolicy from a list of policy paths.
        """
        # Parse the policyIds from the policies path. Only keep the unique ids
        policy_ids = set(
            [
                o['PolicyId']
                for p in policy_paths
                for o in p['Policies']
                if o.get('PolicyId') and o['PolicyType'] == policy_type
            ]
        )

        # retrieve the policies and policy attributes in a batched request
        operations = []
        for policy_id in policy_ids:
            operations.extend([
                {
                    'GetObjectAttributes': {
                        'ObjectReference': {'Selector': f'${policy_id}'},
                        'SchemaFacet': {
                            'SchemaArn': self.node_schema,
                            'FacetName': 'POLICY'
                        },
                        'AttributeNames': ['policy_document']
                    }
                },
                {
                    'GetObjectAttributes': {
                        'ObjectReference': {'Selector': f'${policy_id}'},
                        'SchemaFacet': {
                            'SchemaArn': self._schema,
                            'FacetName': 'IAMPolicy'
                        },
                        'AttributeNames': ['name', 'type']
                    }
                }])

        # parse the policies and attributes from the responses
        responses = cd_client.batch_read(DirectoryArn=self._dir_arn, Operations=operations)['Responses']
        results = defaultdict(list)
        n = 2
        for p, a in [responses[i:i + n] for i in range(0, len(responses), n)]:
            policy = p['SuccessfulResponse']['GetObjectAttributes']['Attributes'][0]['Value'][
                'BinaryValue'].decode('utf-8')
            try:
                attrs = a['SuccessfulResponse']['GetObjectAttributes']['Attributes']
                if attrs[0]['Key']['Name'] == 'name':
                    name = attrs[0]['Value']['StringValue']
                    _type = attrs[1]['Value']['StringValue']
                else:
                    name = attrs[1]['Value']['StringValue']
                    _type = attrs[0]['Value']['StringValue']
                results['policies'].append(
                    {
                        'policy': policy,
                        'type': _type,
                        'name': name
                    }
                )
                results[f'{_type}s'].append(name)
            except KeyError:
                results.append(
                    {
                        'policy': policy,
                        'type': None,
                        'name': None
                    }
                )
        return results

    @retry(**cd_read_retry_parameters)
    def get_object_information(self, obj_ref: str, **kwargs) -> Dict[str, Any]:
        """
        A wrapper around CloudDirectory.Client.get_object_information
        """
        return cd_client.get_object_information(
            DirectoryArn=self._dir_arn,
            ObjectReference={
                'Selector': obj_ref
            },
            **kwargs
        )

    def health_checks(self) -> Dict[str, str]:
        """
        Runs a health check on AWS cloud directory and iam policy simulator
        :return: the status of the services.
        """
        try:
            self.get_object_information('/')['ResponseMetadata']['HTTPStatusCode']
        except Exception:
            return dict(clouddirectory_health_status='unhealthy')
        else:
            return dict(clouddirectory_health_status='ok')

    def make_filter_attribute_range(self,
                                    attribute_name: str,
                                    start_value: str = None,
                                    end_value: str = None,
                                    start_mode: str = 'INCLUSIVE',
                                    end_mode: str = 'INCLUSIVE') -> List[Dict[str, Any]]:
        """
        see https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_range_filters.html
        for"""
        _range = dict()
        if start_value:
            _range.update({'StartMode': start_mode,
                           'StartValue': {'StringValue': start_value}})
        if end_value:
            _range.update({'EndMode': end_mode,
                           'EndValue': {'StringValue': end_value}})

        return [{
            'AttributeName': attribute_name,
            'Range': _range
        }]


class CloudNode:
    """
    Contains shared code across the different types of nodes stored in Fusillade CloudDirectory
    """
    _attributes = ["name"]  # the different attributes of a node stored
    _facet = 'LeafFacet'
    object_type = 'node'

    def __init__(self,
                 name: str = None,
                 object_ref: str = None):
        """

        :param name:
        :param object_ref:
        """
        self.cd: CloudDirectory = Config.get_directory()
        if name and object_ref:
            raise FusilladeException("object_reference XOR name")
        if name:
            self.from_name(name)
        else:
            self._name: str = None
            self._path_name: str = None
            self.object_ref: str = object_ref
        self.attached_policies: Dict[str, str] = dict()

    def from_name(self, name):
        self._name: str = name
        self._path_name: str = self.hash_name(name)
        self.object_ref: str = self.cd.get_obj_type_path(self.object_type) + self._path_name

    @staticmethod
    def hash_name(name):
        """Generate the cloud directory path name from the nodes name."""
        return hashlib.sha1(bytes(name, "utf-8")).hexdigest()

    def _get_link_name(self, parent_path: str, child_path: str):
        return self.hash_name(parent_path + child_path)
        # links names must be unique between two objects

    def _get_links(self, node: Type['CloudNode'],
                   filter_attribute_range: List[Dict[str, Any]],
                   facet,
                   next_token=None,
                   per_page=None,
                   paged=False,
                   incoming=False):
        """
        Retrieves the links attached to this object from CloudDirectory and separates them into groups and roles
        based on the link name
        """
        get_links = self.cd.list_incoming_typed_links if incoming else self.cd.list_outgoing_typed_links
        object_selection = 'SourceObjectReference' if incoming else 'TargetObjectReference'
        if paged:
            result, next_token = get_links(self.object_ref, filter_attribute_range, facet,
                                           next_token=next_token, paged=paged, per_page=per_page)
            if result:
                operations = [self.cd.batch_get_attributes(
                    obj_ref[object_selection]['Selector'],
                    node._facet,
                    ['name'])
                    for obj_ref in result]
                result = []
                for r in self.cd.batch_read(operations)['Responses']:
                    if r.get('SuccessfulResponse'):
                        result.append(
                            r.get('SuccessfulResponse')['GetObjectAttributes']['Attributes'][0]['Value']['StringValue'])
                    else:
                        logger.error({"message": "Batch Request Failed", "response": r})  # log error request failed
            return result, next_token
        else:
            return [
                type_link[object_selection]['Selector']
                for type_link in
                get_links(self.object_ref, filter_attribute_range, facet)
            ]

    def _add_links_batch(self, links: List[Type['CloudNode']]):
        """
        Attaches links to this object in CloudDirectory.
        """
        if not links:
            return []
        batch_attach_object = self.cd.batch_attach_object
        operations = []
        for link in links:
            parent_ref = link.object_ref
            operations.append(
                batch_attach_object(
                    parent_ref,
                    self.object_ref,
                    self._get_link_name(parent_ref, self.object_ref)
                )
            )
        return operations

    def _add_typed_links_batch(self, links: List[Type['CloudNode']], link_type: str, attributes: Dict, incoming=False):
        """
        Attaches links to this object in CloudDirectory.

        TODO modify this function to take in links: List[Type['CloudNode'] and remove the object_type parameter.
        """
        if not links:
            return []
        batch_attach_typed_link = self.cd.batch_attach_typed_link
        operations = []
        for link in links:
            if incoming:
                source, target = link.object_ref, self.object_ref
            else:
                source, target = self.object_ref, link.object_ref
            operations.append(batch_attach_typed_link(source, target, link_type, attributes))
        return operations

    def _remove_links_batch(self, links: List[Type['CloudNode']], incoming=False):
        """
        Removes links from this object in CloudDirectory.
        """
        if not links:
            return []
        batch_detach_object = self.cd.batch_detach_object
        operations = []
        for link in links:
            if incoming:
                source, target = link.object_ref, self.object_ref
            else:
                source, target = self.object_ref, link.object_ref
            operations.append(
                batch_detach_object(
                    target,
                    self._get_link_name(target, source)
                )
            )
        return operations

    def _remove_typed_links_batch(self, links: List[Type['CloudNode']], link_type: str, attributes: Dict,
                                  incoming=False):
        """
        Removes links from this object in CloudDirectory.
        """
        if not links:
            return []
        batch_detach_typed_link = self.cd.batch_detach_typed_link
        make_typed_link_specifier = self.cd.make_typed_link_specifier
        operations = []
        for link in links:
            if incoming:
                source, target = link.object_ref, self.object_ref
            else:
                source, target = self.object_ref, link.object_ref
            typed_link_specifier = make_typed_link_specifier(
                source,
                target,
                link_type,
                attributes
            )
            operations.append(batch_detach_typed_link(typed_link_specifier))
        return operations

    @property
    def name(self):
        if not self._name:
            self._get_attributes(self._attributes)
            self._path_name = self.hash_name(self._name)
        return self._name

    def _get_attributes(self, attributes: List[str]):
        """
        retrieve attributes for this from CloudDirectory and sets local private variables.
        """
        if not attributes:
            attributes = self._attributes
        try:
            resp = self.cd.get_object_attributes(self.object_ref, self._facet, attributes)
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeNotFoundException(detail="Resource does not exist.")
        for attr in resp['Attributes']:
            self.__setattr__('_' + attr['Key']['Name'], attr['Value'].popitem()[1])

    def get_attributes(self, attributes: List[str]) -> Dict[str, str]:
        try:
            resp = self.cd.get_object_attributes(self.object_ref, self._facet, attributes)
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeNotFoundException(detail="Resource does not exist.")
        return dict([(attr['Key']['Name'], attr['Value'].popitem()[1]) for attr in resp['Attributes']])

    def delete_node(self):
        try:
            self.cd.delete_object(self.object_ref)
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeNotFoundException(f"Failed to delete {self.name}. {self.object_type} does not exist.")

    @classmethod
    def list_all(cls, next_token: str = None, per_page: int = None):
        cd = Config.get_directory()
        resp, next_token = cd.list_object_children_paged(f'/{cls.object_type}/', next_token, per_page)
        operations = [cd.batch_get_attributes(f'${obj_ref}', cls._facet, ['name'])
                      for obj_ref in resp.values()]
        results = []
        for r in cd.batch_read(operations)['Responses']:
            if r.get('SuccessfulResponse'):
                results.append(
                    r.get('SuccessfulResponse')['GetObjectAttributes']['Attributes'][0]['Value']['StringValue'])
            else:
                logger.error({"message": "Batch Request Failed", "response": r})  # log error request failed
        return {f"{cls.object_type}s": results}, next_token

    def get_info(self) -> Dict[str, Any]:
        info = dict(**self.get_attributes(self._attributes))
        info[f'{self.object_type}_id'] = info.pop('name')
        return info

    @classmethod
    def _exists(cls, nodes: List[str]):
        operations = []
        directory = Config.get_directory()
        try:
            for node in nodes:
                operations.append(directory.batch_get_object_info(cls(node).object_ref))
            directory.batch_read(operations)
        except cd_client.exceptions.ResourceNotFoundException:
            raise FusilladeBadRequestException(f"One or more {cls.object_type} does not exist.")

    @classmethod
    def get_names(cls, obj_refs: List[str]) -> List[str]:
        cd = Config.get_directory()
        operations = [cd.batch_get_attributes(obj_ref, cls._facet, ['name']) for obj_ref in obj_refs]
        results = []
        for r in cd.batch_read(operations)['Responses']:
            if r.get('SuccessfulResponse'):
                results.append(
                    r.get('SuccessfulResponse')['GetObjectAttributes']['Attributes'][0]['Value']['StringValue'])
            else:
                logger.error({"message": "Batch Request Failed", "response": r})  # log error request failed
        return results

    def list_owners(self, incoming=True):
        get_links = self.cd.list_incoming_typed_links if incoming else self.cd.list_outgoing_typed_links
        object_selection = 'SourceObjectReference' if incoming else 'TargetObjectReference'
        _owners = [
            type_link[object_selection]['Selector']
            for type_link in
            get_links(self.object_ref, filter_typed_link='ownership_link')
        ]
        owners = []
        for owner in _owners:
            node = CloudNode(object_ref=owner)
            owners.append({
                'type': [i for i in
                         [p['Path'].split('/')[1]
                          for p in node.cd.list_object_parent_paths(node.object_ref)] if i != 'role'][0],
                'name': node.name
            })
        return owners


class PolicyMixin:
    """Adds policy support to a cloudNode"""
    allowed_policy_types = ['IAMPolicy']

    def get_authz_params(self) -> Dict[str, Union[List[Dict[str, str]], List[str]]]:
        policy_paths = self.cd.lookup_policy(self.object_ref)
        return self.cd.get_policies(policy_paths)

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
        parent_path = self.cd.get_obj_type_path('policy')
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
                policy_ref = self.cd.get_obj_type_path('policy') + self.get_policy_name(policy_type)
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
                               json.dumps(statement),
                               UpdateActions.CREATE_OR_UPDATE,
                               )
        ]
        try:
            try:
                self.cd.update_object_attribute(self.cd.get_obj_type_path('policy') + self.get_policy_name(policy_type),
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
            new_node.cd.get_obj_type_path(cls.object_type),
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
        if self.is_enabled():
            policy_paths = self.lookup_policies_batched()
        else:
            raise AuthorizationException(f"User {self.status}")
        return self.cd.get_policies(policy_paths)

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
            [json.loads(p['policy'])['Statement'] for p in self.get_authz_params()['policies']]))
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