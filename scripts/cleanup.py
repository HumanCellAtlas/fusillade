import boto3
from fusillade.clouddirectory import cleanup_directory, cleanup_schema
client = boto3.client("clouddirectory")

response = client.list_directories(
    MaxResults=30,
    state='ENABLED'
)

test_directories = [directory['DirectoryArn'] for directory in response['Directories'] if 'test' in directory['Name']]
for directory in test_directories:
    cleanup_directory(directory)

directories = [ i['Name'] for i in client.list_directories(
    MaxResults=30,
    state='ENABLED'
)['Directories']]
print('DIRECTORIES:', directories)





