#!/usr/bin/env python
"""
This script uploads environment variables for deploying fusillade
into AWS Systems Manager Parameter Store under the key
`dcp/fusillade/{FUS_DEPLOYMENT_STAGE}/deployment_environment`.
"""
import argparse
import os

import boto3

ssm_client = boto3.client("ssm")


def get_ssm_deployment_environment():
    parms = ssm_client.get_parameter(
        Name=f"/{os.environ['FUS_PARAMETER_STORE']}/{args.stage}/deployment_environment"
    )['Parameter']['Value']
    return parms


def set_ssm_deployment_environment(parms: str):
    ssm_client.put_parameter(
        Name=f"/dcp/fusillade/{args.stage}/deployment_environment",
        Value=parms,
        Type="String",
        Overwrite=True
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('stage',
                        metavar='stage',
                        type=str,
                        help="The stage you would like to upload the environment variables for.",
                        choices=["master", "dev", "integration", "staging", "prod"])
    parser.add_argument("-p", "--print",
                        default=False,
                        action="store_true",
                        help="Display the current environemnt stored in SSM"
                        )
    parser.add_argument("--file", "-f",
                        type=str,
                        help="path to the environment file."
                        )
    args = parser.parse_args()

    if args.stage == "master":
        args.stage = "dev"
    if args.print:
        try:
            print(get_ssm_deployment_environment())
        except ssm_client.exceptions.ParameterNotFound:
            pass
    elif args.file:
        with open(args.file, 'r') as fp:
            contents = fp.read()
            set_ssm_deployment_environment(contents)
