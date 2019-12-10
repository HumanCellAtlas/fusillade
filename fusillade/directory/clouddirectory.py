import functools
import json
import logging
from collections import defaultdict
from datetime import datetime
from typing import Callable, Optional, Iterator, Tuple, List, Union, Dict, Any

from dcplib.aws.clients import clouddirectory as cd_client
from fusillade.directory.structs import ConsistencyLevel, UpdateObjectParams, ValueTypes
from fusillade.errors import FusilladeException
from fusillade.utils.retry import retry

logger = logging.getLogger(__name__)

cd_read_retry_parameters = dict(timeout=5,
                                delay=0.1,
                                retryable=lambda e: isinstance(e, cd_client.exceptions.RetryableConflictException))
cd_write_retry_parameters = dict(timeout=5,
                                 delay=0.2,
                                 retryable=lambda e: isinstance(e, cd_client.exceptions.RetryableConflictException))


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
                                   per_page: Optional[int] = None, **kwargs) -> Tuple[dict, Optional[str]]:
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
                    BinaryValue=self.format_policy(statement)))
        ])
        return attributes

    @staticmethod
    def format_policy(statement: Dict[str, Any]) -> bytearray:
        statement.update(Version="2012-10-17")
        return json.dumps(statement).encode()

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

    @staticmethod
    def parse_attributes(attributes: List[Dict[str, Any]]) -> Dict[str, Any]:
        result = dict()
        # check if we are parsing object attributes or typed link attributes
        typed_link = attributes[0].get('Key') is None
        for attr in attributes:
            key = attr['AttributeName'] if typed_link else attr['Key']['Name']
            if ValueTypes.StringValue.name in attr['Value'].keys():
                result[key] = attr['Value'][ValueTypes.StringValue.name]
            elif ValueTypes.BinaryValue.name in attr['Value'].keys():
                result[key] = attr['Value'][ValueTypes.BinaryValue.name]
            elif ValueTypes.BooleanValue.name in attr['Value'].keys():
                result[key] = attr['Value'][ValueTypes.BooleanValue.name]
            elif ValueTypes.NumberValue.name in attr['Value'].keys():
                result[key] = attr['Value'][ValueTypes.NumberValue.name]
            elif ValueTypes.DatetimeValue.name in attr['Value'].keys():
                result[key] = attr['Value'][ValueTypes.DatetimeValue.name]
        return result

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

    @batch_reference
    def batch_get_link_attributes(self,
                                  TypedLinkSpecifier: Dict[str, Any],
                                  AttributeNames: List[str]) -> Dict[str, Any]:
        """
        A helper function to format a batch get_attributes operation
        """
        return {
            'GetLinkAttributes': {
                'TypedLinkSpecifier': TypedLinkSpecifier,
                'AttributeNames': AttributeNames
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

    def get_policy_ids(self, policy_paths: List[Dict[str, Any]], policy_type='IAMPolicy'):
        # Parse the policyIds from the policies path. Only keep the unique ids
        return set(
            [
                f"${o['PolicyId']}"
                for p in policy_paths
                for o in p['Policies']
                if o.get('PolicyId') and o['PolicyType'] == policy_type
            ]
        )

    def get_policies(self, policy_ids: List[str]) -> Dict[str, Union[List[Dict[str, str]], List[str]]]:
        """
        Gets policy statements and attributes.

        :param policy_paths: a list of paths leading to policy nodes stored in cloud directory
        :param policy_type: the type of policies to retrieve from the policy nodes
        :return: returns the policies of the type IAMPolicy from a list of policy paths.
        """

        # retrieve the policies and policy attributes in a batched request
        operations = []
        for policy_id in policy_ids:
            operations.extend([
                {
                    'GetObjectAttributes': {
                        'ObjectReference': {'Selector': policy_id},
                        'SchemaFacet': {
                            'SchemaArn': self.node_schema,
                            'FacetName': 'POLICY'
                        },
                        'AttributeNames': ['policy_document', 'policy_type']
                    }
                },
                {
                    'GetObjectAttributes': {
                        'ObjectReference': {'Selector': policy_id},
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
            attributes = p['SuccessfulResponse']['GetObjectAttributes']['Attributes']
            attributes.extend(a['SuccessfulResponse']['GetObjectAttributes']['Attributes'])
            attributes = self.parse_attributes(attributes)
            attributes['policy_document'] = attributes['policy_document'].decode()
            results[attributes['policy_type']].append(
                attributes
            )
            try:
                results[f"{attributes['type']}s"].append(attributes['name'])
            except KeyError:
                pass
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
