#!/usr/bin/env python
"""
Check if your schema is matches the latest in AWS.
Optional you can upgrade the published schema to match your local schema
"""
import os
import sys
import json

import argparse

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

from fusillade.clouddirectory import cd_client, directory_schema_path, get_json_file, project_arn

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--major-version", required=True, type=str, help='The major version of the published schema to '
                                                                     'check/upgrade')
parser.add_argument("--schema-name", required=True, type=str, help='The name of the published schema to check/upgrade')
parser.add_argument("--upgrade", required=False, default=False, type=bool,
                    help='If true the published schema will be upgraded, else compare it with the local and return '
                         'results')

args = parser.parse_args()

# TODO: add cli to check if your schema matches the latest published schema
# TODO: add cli to check if the latest published schema matches your directories schema

# TODO: add cli to upgrade the latest published schema with your local schema
# TODO: add cli to upgrade your directory schema with the latest published schema

name = args.schema_name
version = {'Version': args.major_version, 'MinorVersion': '0'}
outofdate = False

# open schema file locally
new_schema = get_json_file(directory_schema_path)

# check if published schema exists
published_schemas = cd_client.list_published_schema_arns(
    SchemaArn=f"{project_arn}schema/published/{name}/{version['Version']}",
    MaxResults=30)['SchemaArns']
pub_schema_arn = published_schemas[-1]
try:
    published = cd_client.get_schema_as_json(SchemaArn=pub_schema_arn)['Document']
except cd_client.exceptions.ResourceNotFoundException:
    outofdate = True
else:
    # compare new_schema with published
    new = json.loads(new_schema)
    new.pop('sourceSchemaArn')
    new = json.dumps(new, sort_keys=True)
    old = json.loads(published)
    old.pop('sourceSchemaArn')
    old = json.dumps(old, sort_keys=True)

    if new == old:
        print('Schema is up to date!')
    else:
        print("Schema needs to be updated.")
        outofdate = True

if outofdate and args.upgrade:
    try:
        # create a new development schema
        dev_schema_arn = cd_client.create_schema(Name=name)['SchemaArn']
    except cd_client.exceptions.SchemaAlreadyExistsException:
        # if schema exists use that one
        dev_schema_arn = f"{project_arn}schema/development/{name}"
    # update the dev schema
    cd_client.put_schema_from_json(SchemaArn=dev_schema_arn, Document=new_schema)
    try:
        # publish the schema with a minor version
        new_schema_arn = cd_client.publish_schema(DevelopmentSchemaArn=dev_schema_arn, **version)['PublishedSchemaArn']
    except cd_client.exceptions.SchemaAlreadyPublishedException:
        # if version/minor versions exists upgrade
        minor = max([int(i.split('/')[-1]) for i in published_schemas]) + 1
        new_schema_arn = cd_client.upgrade_published_schema(
            DevelopmentSchemaArn=dev_schema_arn,
            PublishedSchemaArn=pub_schema_arn,
            MinorVersion=str(minor),
            DryRun=False
        )['UpgradedSchemaArn']
