"""
clouddrectory.py

This modules is used to simplify access to AWS Cloud Directory. For more information on AWS Cloud Directory see
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/clouddirectory.html

"""
import hashlib
from datetime import datetime
import os
from dcplib.aws import clients as aws_clients
import functools
import json
import typing
from collections import namedtuple
from enum import Enum, auto
from urllib.parse import quote

from fusillade.errors import FusilladeException
from fusillade.config import Config

project_arn = "arn:aws:clouddirectory:us-east-1:861229788715:"  # TODO move to config.py
cd_client = aws_clients.clouddirectory

proj_path = os.path.dirname(__file__)

# TODO make all configurable
directory_schema_path = os.path.join(proj_path, 'directory_schema.json')
default_user_policy_path = os.path.join(proj_path, '..', 'policies', 'default_user_policy.json')
default_group_policy_path = os.path.join(proj_path, '..', 'policies', 'default_group_policy.json')
default_admin_role_path = os.path.join(proj_path, '..', 'policies', 'default_admin_role.json')
default_user_role_path = os.path.join(proj_path, '..', 'policies', 'default_user_role.json')
default_role_path = os.path.join(proj_path, '..', 'policies', 'default_role.json')


def get_json_file(file_name):
    with open(file_name, 'r') as fp:
        return json.dumps(json.load(fp))


def get_published_schema_from_directory(dir_arn: str) -> str:
    schema = cd_client.list_applied_schema_arns(DirectoryArn=dir_arn)['SchemaArns'][0]
    schema = schema.split('/')[-2:]
    schema = '/'.join(schema)
    return f"{project_arn}schema/published/{schema}"


def cleanup_directory(dir_arn: str):
    cd_client.disable_directory(DirectoryArn=dir_arn)
    cd_client.delete_directory(DirectoryArn=dir_arn)


def cleanup_schema(sch_arn: str) -> None:
    cd_client.delete_schema(SchemaArn=sch_arn)


def publish_schema(name: str, version: str) -> str:
    """
    More info about schemas
    https://docs.aws.amazon.com/clouddirectory/latest/developerguide/schemas.html
    """
    # don't create if already created
    try:
        dev_schema_arn = cd_client.create_schema(Name=name)['SchemaArn']
    except cd_client.exceptions.SchemaAlreadyExistsException:
        dev_schema_arn = f"{project_arn}schema/development/{name}"

    # update the schema
    schema = get_json_file(directory_schema_path)
    cd_client.put_schema_from_json(SchemaArn=dev_schema_arn, Document=schema)
    try:
        pub_schema_arn = cd_client.publish_schema(DevelopmentSchemaArn=dev_schema_arn,
                                                  Version=version)['PublishedSchemaArn']
    except cd_client.exceptions.SchemaAlreadyPublishedException:
        pub_schema_arn = f"{project_arn}schema/published/{name}/{version}"
    return pub_schema_arn


def create_directory(name: str, schema: str) -> 'CloudDirectory':
    """
    Retrieve the fusillade cloud directory or do a one time setup of cloud directory to be used with fusillade.

    :param name:
    :param schema:
    :return:
    """
    try:
        response = cd_client.create_directory(
            Name=name,
            SchemaArn=schema
        )
        directory = CloudDirectory(response['DirectoryArn'])
    except cd_client.exceptions.DirectoryAlreadyExistsException:
        directory = CloudDirectory.from_name(name)
    else:
        # create structure
        for folder_name in ('group', 'user', 'role', 'policy'):
            directory.create_folder('/', folder_name)

        # create roles
        Role.create(directory, "default_user", statement=get_json_file(default_user_role_path))
        Role.create(directory, "admin", statement=get_json_file(default_admin_role_path))

        # create admins
        for admin in Config.get_admin_emails():
            User.provision_user(directory, admin, roles=['admin'])
    return directory


def _paging_loop(fn: typing.Callable, key: str, upack_response: typing.Callable, **kwarg):
    while True:
        resp = fn(**kwarg)
        for i in resp[key]:
            yield upack_response(i)
        kwarg['NextToken'] = resp.get("NextToken")
        if not kwarg['NextToken']:
            break


def list_directories(state: str = 'ENABLED') -> typing.Iterator:
    def unpack_response(i):
        return i

    return _paging_loop(cd_client.list_directories, 'Directories', unpack_response, state=state)


class UpdateActions(Enum):
    CREATE_OR_UPDATE = auto()
    DELETE = auto()


class ValueTypes(Enum):
    StringValue = auto()
    BinaryValue = auto()
    BooleanValue = auto()
    NumberValue = auto()
    DatetimeValue = auto()


class UpdateObjectParams(namedtuple("UpdateObjectParams", ['facet', 'attribute', 'value_type', 'value', 'action'])):
    pass


class CloudDirectory:
    _page_limit = 30  # This is the max allowed by AWS

    def __init__(self, directory_arn: str):
        self._dir_arn = directory_arn
        self._schema = None

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

    def list_object_children(self, object_ref: str) -> typing.Iterator[typing.Tuple[str, str]]:
        """
        a wrapper around CloudDirectory.Client.list_object_children with paging
        """
        resp = cd_client.list_object_children(DirectoryArn=self._dir_arn,
                                              ObjectReference={'Selector': object_ref},
                                              ConsistencyLevel='EVENTUAL',
                                              MaxResults=self._page_limit)
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
                            IncludeAllLinksToEachParent: bool = True) -> typing.Iterator:
        """
        a wrapper around CloudDirectory.Client.list_object_parents with paging
        """
        if IncludeAllLinksToEachParent:
            def unpack_response(i):
                return '$' + i['ObjectIdentifier'], i['LinkName']

            return _paging_loop(cd_client.list_object_parents,
                                'ParentLinks',
                                unpack_response,
                                DirectoryArn=self._dir_arn,
                                ObjectReference={'Selector': object_ref},
                                ConsistencyLevel='EVENTUAL',
                                IncludeAllLinksToEachParent=IncludeAllLinksToEachParent,
                                MaxResults=self._page_limit
                                )
        else:
            return _paging_loop(cd_client.list_object_parents,
                                'Parents',
                                self._make_ref,
                                DirectoryArn=self._dir_arn,
                                ObjectReference={'Selector': object_ref},
                                ConsistencyLevel='EVENTUAL',
                                IncludeAllLinksToEachParent=IncludeAllLinksToEachParent,
                                MaxResults=self._page_limit
                                )

    def list_object_policies(self, object_ref: str) -> typing.Iterator[str]:
        """
        a wrapper around CloudDirectory.Client.list_object_policies with paging
        """
        return _paging_loop(cd_client.list_object_policies,
                            'AttachedPolicyIds',
                            self._make_ref,
                            DirectoryArn=self._dir_arn,
                            ObjectReference={'Selector': object_ref},
                            MaxResults=self._page_limit
                            )

    def list_policy_attachments(self, policy: str) -> typing.Iterator[str]:
        """
        a wrapper around CloudDirectory.Client.list_policy_attachments with paging
        """
        return _paging_loop(cd_client.list_policy_attachments,
                            'ObjectIdentifiers',
                            self._make_ref,
                            DirectoryArn=self._dir_arn,
                            PolicyReference={'Selector': policy},
                            MaxResults=self._page_limit
                            )

    def _list_typed_links(self,
                          func: typing.Callable,
                          key: str,
                          object_ref: str,
                          filter_attribute_ranges: typing.Optional[typing.List],
                          filter_typed_link: typing.Optional[str]
                          ):
        def unpack_response(i):
            return i

        kwargs = dict(
            DirectoryArn=self._dir_arn,
            ObjectReference={'Selector': object_ref},
            MaxResults=self._page_limit
        )
        if filter_attribute_ranges:
            kwargs['FilterAttributeRanges'] = filter_attribute_ranges
        if filter_typed_link:
            kwargs['FilterTypedLink'] = {
                'SchemaArn': self.schema,
                'TypedLinkName': filter_typed_link
            }
        return _paging_loop(func, key, unpack_response, **kwargs)

    def list_outgoing_typed_links(self,
                                  object_ref: str,
                                  filter_attribute_ranges: typing.List = None,
                                  filter_typed_link: str = None) -> typing.Iterator[dict]:
        """
        a wrapper around CloudDirectory.Client.list_outgoing_typed_links

        :return: typed link specifier generator
        """
        return self._list_typed_links(cd_client.list_outgoing_typed_links,
                                      'TypedLinkSpecifiers',
                                      object_ref,
                                      filter_attribute_ranges,
                                      filter_typed_link)

    def list_incoming_typed_links(self,
                                  object_ref: str,
                                  filter_attribute_ranges: typing.List = None,
                                  filter_typed_link: str = None) -> typing.Iterator[dict]:
        """
        a wrapper around CloudDirectory.Client.list_incoming_typed_links

        :return: typed link specifier generator
        """
        return self._list_typed_links(cd_client.list_incoming_typed_links,
                                      'LinkSpecifiers',
                                      object_ref,
                                      filter_attribute_ranges,
                                      filter_typed_link)

    @staticmethod
    def _make_ref(i):
        return '$' + i

    def create_object(self, link_name: str, facet_type: str, obj_type: str, **kwargs) -> str:
        """
        Create an object and store in cloud directory.
        """
        object_attribute_list = self._get_object_attribute_list(facet=facet_type, obj_type=obj_type, **kwargs)
        parent_path = self.get_obj_type_path(obj_type)
        cd_client.create_object(DirectoryArn=self._dir_arn,
                                SchemaFacets=[
                                    {
                                        'SchemaArn': self.schema,
                                        'FacetName': facet_type
                                    },
                                ],
                                ObjectAttributeList=object_attribute_list,
                                ParentReference=dict(Selector=parent_path),
                                LinkName=link_name)
        object_ref = parent_path + link_name
        return object_ref

    def get_object_attributes(self, obj_ref: str, facet: str, attributes: typing.List[str]) -> typing.Dict[str, str]:
        """
        a wrapper around CloudDirectory.Client.get_object_attributes
        """
        return cd_client.get_object_attributes(DirectoryArn=self._dir_arn,
                                               ObjectReference={'Selector': obj_ref},
                                               SchemaFacet={
                                                   'SchemaArn': self.schema,
                                                   'FacetName': facet
                                               },
                                               AttributeNames=attributes
                                               )

    def _get_object_attribute_list(self, facet="User", **kwargs) -> typing.List[typing.Dict[str, typing.Any]]:
        return [dict(Key=dict(SchemaArn=self.schema, FacetName=facet, Name=k), Value=dict(StringValue=v))
                for k, v in kwargs.items()]

    def get_policy_attribute_list(self,
                                  policy_type: str,
                                  statement: str,
                                  facet: str = "IAMPolicy",
                                  **kwargs) -> typing.List[typing.Dict[str, typing.Any]]:
        """
        policy_type and policy_document are required field for a policy object. However only policy_type is used by
        fusillade. Statement is used to store policy information. See the section on Policies for more
        info https://docs.aws.amazon.com/clouddirectory/latest/developerguide/key_concepts_directory.html
        """
        kwargs["Statement"] = statement
        obj = self._get_object_attribute_list(facet=facet, **kwargs)
        obj.append(dict(Key=dict(
            SchemaArn=self.schema,
            FacetName=facet,
            Name='policy_type'),
            Value=dict(StringValue=f"{policy_type}_{facet}")))
        obj.append(
            dict(Key=dict(SchemaArn=self.schema,
                          FacetName=facet,
                          Name="policy_document"),
                 Value=dict(BinaryValue='None'.encode())))
        return obj

    def update_object_attribute(self,
                                object_ref: str,
                                update_params: typing.List[UpdateObjectParams]) -> typing.Dict[str, typing.Any]:
        """
        a wrapper around CloudDirectory.Client.update_object_attributes

        :param object_ref: The reference that identifies the object.
        :param update_params: a list of attributes to modify.
        :return:
        """
        updates = [
            {
                'ObjectAttributeKey': {
                    'SchemaArn': self.schema,
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

    def create_folder(self, path: str, name: str) -> None:
        """ A folder is just a Group"""
        schema_facets = [dict(SchemaArn=self.schema, FacetName="BasicFacet")]
        object_attribute_list = self._get_object_attribute_list(facet="BasicFacet", name=name, obj_type="folder")
        try:
            cd_client.create_object(DirectoryArn=self._dir_arn,
                                    SchemaFacets=schema_facets,
                                    ObjectAttributeList=object_attribute_list,
                                    ParentReference=dict(Selector=path),
                                    LinkName=name)
        except cd_client.exceptions.LinkNameAlreadyInUseException:
            pass

    def attach_typed_link(
            self,
            source: str,
            target: str,
            typed_link_facet: str,
            attributes: typing.Dict[str, typing.Any]):
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
            Attributes=attributes
        )

    def detach_typed_link(self, typed_link_specifier: typing.Dict):
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
    def make_attributes(kwargs: typing.Dict) -> typing.List:
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
            attributes: typing.Dict):
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

    def clear(self) -> None:
        for _, obj_ref in self.list_object_children('/user/'):
            self.delete_object(obj_ref)
        for _, obj_ref in self.list_object_children('/group/'):
            self.delete_object(obj_ref)
        for name, obj_ref in self.list_object_children('/role/'):
            if name not in ["admin", "default_user"]:
                self.delete_object(obj_ref)

    def delete_policy(self, policy_ref: str) -> None:
        """
        See details on deletion requirements for more info
        https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html
        """
        self.batch_write([self.batch_detach_policy(policy_ref, obj_ref)
                          for obj_ref in self.list_policy_attachments(policy_ref)])
        self.batch_write([self.batch_detach_object(parent_ref, link_name)
                          for parent_ref, link_name in self.list_object_parents(policy_ref)])
        cd_client.delete_object(DirectoryArn=self._dir_arn, ObjectReference={'Selector': policy_ref})

    def delete_object(self, obj_ref: str) -> None:
        """
        See details on deletion requirements for more info
        https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html
        """
        [self.delete_policy(policy_ref) for policy_ref in self.list_object_policies(obj_ref)]
        self.batch_write([self.batch_detach_object(parent_ref, link_name)
                          for parent_ref, link_name in self.list_object_parents(obj_ref)])
        self.batch_write([self.batch_detach_typed_link(i) for i in self.list_incoming_typed_links(object_ref=obj_ref)])
        self.batch_write([self.batch_detach_typed_link(i) for i in self.list_outgoing_typed_links(obj_ref)])
        cd_client.delete_object(DirectoryArn=self._dir_arn, ObjectReference={'Selector': obj_ref})

    @staticmethod
    def batch_detach_policy(policy_ref: str, object_ref: str):
        """
        A helper function to format a batch detach_policy operation
        """
        return {
            'DetachPolicy': {
                'PolicyReference': {'Selector': policy_ref},
                'ObjectReference': {'Selector': object_ref}
            }
        }

    def batch_create_object(self, parent: str,
                            name: str,
                            facet_name: str,
                            object_attribute_list: typing.List[str]) -> typing.Dict[str, typing.Any]:
        """
        A helper function to format a batch create_object operation
        """
        return {'CreateObject': {
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
            'LinkName': name,
        }
        }

    def batch_get_attributes(self, obj_ref, facet, attributes: typing.List[str]) -> typing.Dict[str, typing.Any]:
        """
        A helper function to format a batch get_attributes operation
        """
        return {
            'GetObjectAttributes': {
                'ObjectReference': {
                    'Selector': obj_ref
                },
                'SchemaFacet': {
                    'SchemaArn': self.schema,
                    'FacetName': facet
                },
                'AttributeNames': attributes
            }
        }

    @staticmethod
    def batch_attach_object(parent: str, child: str, name: str) -> typing.Dict[str, typing.Any]:
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
    def batch_detach_object(parent: str, link_name: str) -> typing.Dict[str, typing.Any]:
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
    def batch_attach_policy(policy: str, object_ref: str) -> typing.Dict[str, typing.Any]:
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

    def batch_attach_typed_link(self,
                                source_ref: str,
                                target_ref: str,
                                facet_name: str,
                                attributes: typing.Dict) -> typing.Dict[str, typing.Any]:
        return {
            'AttachTypedLink': {
                'SourceObjectReference': {
                    'Selector': source_ref
                },
                'TargetObjectReference': {
                    'Selector': target_ref
                },
                'TypedLinkFacet': {
                    'SchemaArn': self.schema,
                    'TypedLinkName': facet_name
                },
                'Attributes': self.make_attributes(attributes)
            }
        }

    @staticmethod
    def batch_detach_typed_link(typed_link_specifier) -> typing.Dict[str, typing.Any]:
        return {
            'DetachTypedLink': {
                'TypedLinkSpecifier': typed_link_specifier
            },
        }

    def batch_write(self, operations: list) -> typing.Dict[str, typing.Any]:
        """
        A wrapper around CloudDirectory.Client.batch_write
        """
        return cd_client.batch_write(DirectoryArn=self._dir_arn, Operations=operations)

    def batch_read(self, operations: typing.List[typing.Dict[str, typing.Any]]) -> typing.Dict[str, typing.Any]:
        """
        A wrapper around CloudDirectory.Client.batch_read
        """
        return cd_client.batch_read(DirectoryArn=self._dir_arn, Operations=operations)

    @staticmethod
    def get_obj_type_path(obj_type: str) -> str:
        obj_type = obj_type.lower()
        paths = dict(group='/group/',
                     index='/index/',
                     user='/user/',
                     policy='/policy/',
                     role='/role/')
        return paths[obj_type]

    def lookup_policy(self, object_id: str) -> typing.List[str]:
        max_results = 3  # Max recommended by AWS Support

        # retrieve all of the policies attached to an object and its parents.
        response = cd_client.lookup_policy(
            DirectoryArn=self._dir_arn,
            ObjectReference={'Selector': object_id},
            MaxResults=max_results
        )
        policies_paths: list = response['PolicyToPathList']
        while response.get('NextToken'):
            response = cd_client.lookup_policy(
                DirectoryArn=self._dir_arn,
                ObjectReference={'Selector': object_id},
                NextToken=response['NextToken'],
                MaxResults=max_results
            )
            policies_paths.extend(response['PolicyToPathList'])

        # Parse the policyIds from the policies path. Only keep the unique ids
        policy_ids = set(
            [
                (o['PolicyId'], o['PolicyType'])
                for p in policies_paths
                for o in p['Policies']
                if o.get('PolicyId')
            ]
        )

        # retrieve the policies in a single request
        operations = [
            {
                'GetObjectAttributes': {
                    'ObjectReference': {'Selector': f'${policy_id[0]}'},
                    'SchemaFacet': {
                        'SchemaArn': self.schema,
                        'FacetName': 'IAMPolicy'
                    },
                    'AttributeNames': ['Statement']
                }
            }
            for policy_id in policy_ids
        ]

        # parse the policies from the responses
        policies = [
            response['SuccessfulResponse']['GetObjectAttributes']['Attributes'][0]['Value']['StringValue']
            for response in cd_client.batch_read(DirectoryArn=self._dir_arn, Operations=operations)['Responses']
        ]
        return policies

    def get_object_information(self, obj_ref: str) -> typing.Dict[str, typing.Any]:
        """
        A wrapper around CloudDirectory.Client.get_object_information
        """
        return cd_client.get_object_information(
            DirectoryArn=self._dir_arn,
            ObjectReference={
                'Selector': obj_ref
            },
            ConsistencyLevel='EVENTUAL'
        )


class CloudNode:
    """
    Contains shared code across the different types of nodes stored in Fusillade CloudDirectory
    """
    _attributes = ["name"]  # the different attributes of a node stored

    def __init__(self,
                 cloud_directory: CloudDirectory,
                 object_type: str,
                 name: str = None,
                 object_ref: str = None,
                 facet="BasicFacet"):
        """

        :param cloud_directory:
        :param object_type:
        :param name:
        :param object_reference:
        :param facet:
        """
        if name and object_ref:
            raise FusilladeException("object_reference XOR name")
        if name:
            self._name: str = name
            self._path_name: str = quote(name)
            self.object_ref: str = cloud_directory.get_obj_type_path(object_type) + self._path_name
        else:
            self._name: str = None
            self._path_name: str = None
            self.object_ref: str = object_ref
        self._object_type: str = object_type
        self._facet: str = facet
        self.cd: CloudDirectory = cloud_directory
        self._policy: typing.Optional[str] = None
        self._statement: typing.Optional[str] = None

    @staticmethod
    def _get_link_name(parent_path: str, child_path: str):
        return hashlib.sha1(bytes(parent_path + child_path, "utf-8")).hexdigest()
        # links names must be unique between two objects

    def _get_links(self, object_type):
        """
        Retrieves the links attached to this object from CloudDirectory and separates them into groups and roles
        based on the link name
        """
        filter_attribute_ranges = [
            {
                'AttributeName': 'parent_type',
                'Range': {
                    'StartMode': 'INCLUSIVE',
                    'StartValue': {'StringValue': object_type},
                    'EndMode': 'INCLUSIVE',
                    'EndValue': {'StringValue': object_type}
                }
            }
        ]
        return [
            type_link['SourceObjectReference']['Selector']
            for type_link in self.cd.list_incoming_typed_links(self.object_ref, filter_attribute_ranges, 'association')
        ]

    def _add_links(self, links: typing.List[str], link_type: str):
        """
        Attaches links to this object in CloudDirectory.
        """
        if not links:
            return
        parent_path = self.cd.get_obj_type_path(link_type)
        batch_attach_object = self.cd.batch_attach_object
        batch_attach_typed_link = self.cd.batch_attach_typed_link
        operations = []
        for link in links:
            parent_ref = parent_path + link  # TODO use f-string
            operations.append(
                batch_attach_object(
                    parent_ref,
                    self.object_ref,
                    self._get_link_name(parent_ref, self.object_ref)
                )
            )
            attributes = {
                'parent_type': link_type,
                'child_type': self._object_type,
            }
            operations.append(
                batch_attach_typed_link(
                    parent_ref,
                    self.object_ref,
                    'association',
                    attributes
                )
            )
        self.cd.batch_write(operations)

    def _remove_links(self, links: typing.List[str], link_type: str):
        """
        Removes links from this object in CloudDirectory.
        """
        if not links:
            return
        parent_path = self.cd.get_obj_type_path(link_type)
        batch_detach_object = self.cd.batch_detach_object
        batch_detach_typed_link = self.cd.batch_detach_typed_link
        make_typed_link_specifier = self.cd.make_typed_link_specifier
        operations = []
        for link in links:
            parent_ref = parent_path + link
            operations.append(
                batch_detach_object(
                    parent_ref,
                    self._get_link_name(parent_ref, self.object_ref)
                )
            )
            typed_link_specifier = make_typed_link_specifier(
                parent_ref,
                self.object_ref,
                'association',
                {'parent_type': link_type, 'child_type': self._object_type}
            )
            operations.append(batch_detach_typed_link(typed_link_specifier))
        self.cd.batch_write(operations)

    def lookup_policies(self) -> typing.List[str]:
        return self.cd.lookup_policy(self.object_ref)

    @property
    def name(self):
        if not self._name:
            self._get_attributes(self._attributes)
            self._path_name = quote(self._name)
        return self._name

    @property
    def policy(self):
        if not self._policy:
            policies = [i for i in self.cd.list_object_policies(self.object_ref)]
            if not policies:
                return None
            elif len(policies) > 1:
                raise ValueError("Node has multiple policies attached")
            else:
                self._policy = policies[0]
        return self._policy

    def create_policy(self, statement: str, ) -> str:
        """
        Create a policy object and attach it to the CloudNode
        :param statement: Json string that follow AWS IAM Policy Grammar.
          https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
        :return:
        """
        operations = list()
        object_attribute_list = self.cd.get_policy_attribute_list(self._facet, statement)
        policy_link_name = f"{self._path_name}_{self._object_type}_IAMPolicy"
        parent_path = self.cd.get_obj_type_path('policy')
        operations.append(self.cd.batch_create_object(parent_path,
                                                      policy_link_name,
                                                      'IAMPolicy',
                                                      object_attribute_list))
        policy_ref = parent_path + policy_link_name

        operations.append(self.cd.batch_attach_policy(policy_ref, self.object_ref))
        self.cd.batch_write(operations)
        return policy_ref

    @property
    def statement(self):
        """
        Policy statements follow AWS IAM Policy Grammer. See for grammar details
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
        """
        if not self._statement and self.policy:
            self._statement = self.cd.get_object_attributes(self.policy,
                                                            'IAMPolicy',
                                                            ['Statement'])['Attributes'][0]['Value'].popitem()[1]

        return self._statement

    @statement.setter
    def statement(self, statement: str):
        self._verify_statement(statement)
        self._set_statement(statement)

    def _set_statement(self, statement: str):
        if not self.policy:
            self.create_policy(statement)
        else:
            params = [
                UpdateObjectParams('IAMPolicy',
                                   'Statement',
                                   ValueTypes.StringValue,
                                   statement,
                                   UpdateActions.CREATE_OR_UPDATE)
            ]
            self.cd.update_object_attribute(self.policy, params)
        self._statement = None

    def _get_attributes(self, attributes: typing.List[str]):
        """
        retrieve attributes for this from CloudDirectory and sets local private variables.
        """
        resp = self.cd.get_object_attributes(self.object_ref, self._facet, attributes)
        for attr in resp['Attributes']:
            self.__setattr__('_' + attr['Key']['Name'], attr['Value'].popitem()[1])

    def get_attributes(self, attributes: typing.List[str]):
        attrs = dict()
        if not attributes:
            return attrs
        resp = self.cd.get_object_attributes(self.object_ref, self._facet, attributes)
        for attr in resp['Attributes']:
            attrs[attr['Key']['Name']] = attr['Value'].popitem()[1]  # noqa
        return attrs

    @staticmethod
    def _verify_statement(statement):
        """
        Verifies the policy statement is syntactically correct based on AWS's IAM Policy Grammar.
        A fake ActionNames and ResourceArns are used to facilitate the simulation of the policy.
        """
        iam = aws_clients.iam
        try:
            iam.simulate_custom_policy(PolicyInputList=[statement],
                                       ActionNames=["fake:action"],
                                       ResourceArns=["arn:aws:iam::123456789012:user/Bob"])
        except iam.exceptions.InvalidInputException as ex:
            raise FusilladeException from ex


class User(CloudNode):
    """
    Represents a user in CloudDirectory
    """
    _attributes = ['status'] + CloudNode._attributes
    default_roles = ['default_user']  # TODO: make configurable
    default_groups = []  # TODO: make configurable

    def __init__(self, cloud_directory: CloudDirectory, name: str = None, object_ref: str = None):
        """

        :param cloud_directory:
        :param name:
        """
        super(User, self).__init__(cloud_directory,
                                   'user',
                                   name=name,
                                   object_ref=object_ref,
                                   facet='UserFacet')
        self._status = None
        self._groups: typing.Optional[typing.List[str]] = None
        self._roles: typing.Optional[typing.List[str]] = None

    def lookup_policies(self) -> typing.List[str]:
        try:
            policies = self.cd.lookup_policy(self.object_ref)
        except cd_client.exceptions.ResourceNotFoundException:
            self.provision_user(self.cd, self.name)
            policies = self.cd.lookup_policy(self.object_ref)
        return policies

    @property
    def status(self):
        if not self._status:
            self._get_attributes(['status'])
        return self._status

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
        self._status = None

    @classmethod
    def provision_user(
            cls,
            cloud_directory: CloudDirectory,
            name: str,
            statement: typing.Optional[str] = None,
            roles: typing.List[str] = None,
            groups: typing.List[str] = None,
    ) -> 'User':
        """
        Creates a user in cloud directory if the users does not already exists.

        :param statement: A policy to apply to the user.
        :param roles: a list of roles to add to user
        :param groups: a list of groups to add the user to.
        :return:
        """
        user = cls(cloud_directory, name)
        try:
            user.cd.create_object(user._path_name,
                                  user._facet,
                                  name=user.name,
                                  status='Enabled',
                                  obj_type='user'
                                  )
        except cd_client.exceptions.LinkNameAlreadyInUseException:
            raise FusilladeException("User already exists.")

        if roles:
            user.add_roles(roles + cls.default_roles)
        else:
            user.add_roles(cls.default_roles)

        if groups:
            user.add_groups(groups + cls.default_groups)
        else:
            user.add_groups(cls.default_groups)

        if statement:  # TODO make using user default configurable
            user.statement = statement
        return user

    @property
    def groups(self) -> typing.List[str]:
        if not self._groups:
            self._groups = self._get_links('group')
        return self._groups

    def add_groups(self, groups: typing.List[str]):
        self._add_links(groups, 'group')
        self._groups = None  # update groups

    def remove_groups(self, groups: typing.List[str]):
        self._remove_links(groups, 'group')
        self._groups = None  # update groups

    @property
    def roles(self) -> typing.List[str]:
        if not self._roles:
            self._roles = self._get_links('role')
        return self._roles

    def add_roles(self, roles: typing.List[str]):
        self._add_links(roles, 'role')
        self._roles = None  # update roles

    def remove_roles(self, roles: typing.List[str]):
        self._remove_links(roles, 'role')
        self._roles = None  # update roles


class Group(CloudNode):
    """
    Represents a group in CloudDirectory
    """

    def __init__(self, cloud_directory: CloudDirectory, name: str = None, object_ref: str = None):
        """

        :param cloud_directory:
        :param name:
        """
        super(Group, self).__init__(cloud_directory, 'group', name=name, object_ref=object_ref)
        self._groups = None
        self._roles = None

    @classmethod
    def create(cls,
               cloud_directory: CloudDirectory,
               name: str,
               statement: typing.Optional[str] = None) -> 'Group':
        if not statement:
            statement = get_json_file(default_group_policy_path)
        cls._verify_statement(statement)
        cloud_directory.create_object(quote(name), 'BasicFacet', name=name, obj_type="group")
        new_node = cls(cloud_directory, name)
        new_node._set_statement(statement)
        return new_node

    def get_users(self) -> typing.Iterator[typing.Tuple[str, str]]:
        """
        Retrieves the object_refs for all user in this group.
        :return: (user name, user object reference)
        """
        for link, object_ref in self.cd.list_object_children(self.object_ref):
            yield User(self.cd, object_ref).name, object_ref

    @property
    def roles(self):
        if not self._roles:
            self._roles = self._get_links('role')
        return self._roles

    def add_roles(self, roles: typing.List[str]):
        self._add_links(roles, 'role')
        self._roles = None  # update roles

    def remove_roles(self, roles: typing.List[str]):
        self._remove_links(roles, 'role')
        self._roles = None  # update roles

    def add_users(self, users: typing.List[User]) -> None:
        if users:
            operations = [
                self.cd.batch_attach_object(self.object_ref,
                                            i.object_ref,
                                            self._get_link_name(self.object_ref, i.object_ref))
                for i in users]
            self.cd.batch_write(operations)

    def remove_users(self, users: typing.List[str]) -> None:
        """
        Removes users from this group.

        :param users: a list of user names to remove from group
        :return:
        """
        for user in users:
            User(self.cd, user).remove_groups([self._path_name])


class Role(CloudNode):
    """
    Represents a role in CloudDirectory
    """

    def __init__(self, cloud_directory: CloudDirectory, name: str = None, object_ref: str = None):
        super(Role, self).__init__(cloud_directory, 'role', name=name, object_ref=object_ref)

    @classmethod
    def create(cls,
               cloud_directory: CloudDirectory,
               name: str,
               statement: typing.Optional[str] = None) -> 'Role':
        if not statement:
            statement = get_json_file(default_role_path)
        cls._verify_statement(statement)
        cloud_directory.create_object(quote(name), 'BasicFacet', name=name, obj_type='role')
        new_node = cls(cloud_directory, name)
        new_node._set_statement(statement)
        return new_node
