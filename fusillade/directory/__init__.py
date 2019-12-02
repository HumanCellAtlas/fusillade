"""
clouddrectory.py

This modules is used to simplify access to AWS Cloud Directory. For more information on AWS Cloud Directory see
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/clouddirectory.html

"""
import logging
import os
from typing import List

from dcplib.aws import clients as aws_clients
from fusillade.config import proj_path
from fusillade.directory.clouddirectory import CloudDirectory
from fusillade.directory.cloudnode import CloudNode
from fusillade.directory.identifiers import obj_type_path, get_obj_type_path
from fusillade.directory.principal import User, Group, Role
from fusillade.directory.resource import ResourceType
from fusillade.directory.structs import UpdateActions, ValueTypes, ConsistencyLevel, UpdateObjectParams
from fusillade.utils.json import get_json_file

logger = logging.getLogger(__name__)

cd_client = aws_clients.clouddirectory
project_arn = "arn:aws:clouddirectory:{}:{}:".format(
    os.getenv('AWS_DEFAULT_REGION'),
    aws_clients.sts.get_caller_identity().get('Account'))

# TODO make all configurable
directory_schema_path = os.path.join(proj_path, 'directory_schema.json')
default_user_policy_path = os.path.join(proj_path, '..', 'policies', 'default_user_policy.json')
default_admin_role_path = os.path.join(proj_path, '..', 'policies', 'default_admin_role.json')
default_user_role_path = os.path.join(proj_path, '..', 'policies', 'default_user_role.json')


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
             roles: List[str] = None,
             resources: List[str] = None) -> None:
    """
    :param directory: the directory to clear
    :param users: a list of users to keep
    :param groups: a list of groups to keep
    :param roles: a list of roles to keep
    :param resources: a list of resource types to keep
    :return:
    """
    users = users if users else []
    groups = groups if groups else []
    roles = roles if roles else []
    protected_users = [User.hash_name(name) for name in ['public'] + users]
    protected_groups = [Group.hash_name(name) for name in ['user_default'] + groups]
    protected_roles = [Role.hash_name(name) for name in ["fusillade_admin", "default_user"] + roles]
    protected_resources = [ResourceType.hash_name(name) for name in resources]

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
        if name not in protected_resources:
            directory.delete_object(obj_ref, delete_children=True)
