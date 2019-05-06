#!/usr/bin/env python
from fusillade.clouddirectory import cleanup_directory, cleanup_schema, cd_client
"""
This script is used to clean up test directories and schemas from aws clouddirectory
"""


if __name__ == "__main__":
    for response in cd_client.get_paginator('list_directories').paginate(MaxResults=30, state='ENABLED'):
        for directory in response['Directories']:
            if 'test' in directory['Name']:
                cleanup_directory(directory['DirectoryArn'])

    directories = [
        i['Name'] for i in cd_client.list_directories(
            MaxResults=30,
            state='ENABLED'
        )['Directories']
    ]
    print('DIRECTORIES:')
    for i in directories:
        print('\t', i)

    for response in cd_client.get_paginator('list_published_schema_arns').paginate(MaxResults=30):
        for schema in response['SchemaArns']:
            if "authz/T" in schema:
                cleanup_schema(schema)

    schemas = cd_client.list_published_schema_arns(
        MaxResults=30
    )['SchemaArns']
    print('Schemas:')
    for i in schemas:
        print('\t', i)