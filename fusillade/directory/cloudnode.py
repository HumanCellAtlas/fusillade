import hashlib
import logging
from typing import Dict, Type, List, Any

from dcplib.aws.clients import clouddirectory as cd_client
from fusillade.config import Config
from fusillade.directory.clouddirectory import CloudDirectory
from fusillade.directory.identifiers import get_obj_type_path
from fusillade.errors import FusilladeNotFoundException, FusilladeBadRequestException, FusilladeException

logger = logging.getLogger(__name__)


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
        self.object_ref: str = get_obj_type_path(self.object_type) + self._path_name

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
