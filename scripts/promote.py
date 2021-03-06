#!/usr/bin/env python
"""
A tool for promoting server code to different stages, and minting new releases in github.

In order to release you must have a github access token with permissions to write to your repository. Set
environment variable `GITHUB_TOKEN_PATH` to the path of a file which contains github access token, or set environment
variable `GITHUB_TOKEN_SECRET_NAME` to the path of the AWS secret which contains github access token.

`./promote.py integration` promotes master to integration and creates a prerelease in github.
`./promote.py staging` promotes integration to staging and creates a prerelease in github.
`./promote.py prod` promotes staging to prod and creates a release in github.

Versioning follows https://semver.org/ standard
"""
import argparse
import json
import os
import subprocess

import requests
import semver

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('stage',
                    metavar='stage',
                    type=str,
                    help="The stage you would like to create a release to.",
                    choices=["integration", "staging", "prod"])
parser.add_argument('--release', '-r',
                    type=str,
                    choices=["major", "minor", "patch", "prerelease"],
                    default=None,
                    required=False,
                    help="The type of release to produce.")
parser.add_argument('--force', '-f',
                    action="store_true")
parser.add_argument('--release-notes', type=str, required=False,
                    help="The path to a text file containing the release notes.")
parser.add_argument('--dry-run', '-d',
                    action="store_true")
args = parser.parse_args()

repo = 'HumanCellAtlas/fusillade'

if args.stage == 'prod':
    if args.release:
        print(f'Warning: cannot release "prod" with a release type.\n'
              f'Specify no release type to produce a finalized version.')
        exit(1)

if args.stage == 'staging' and args.release:
    print(f'Warning: cannot release "staging" with a release type.\n'
          f'Do not specify a release type.  The version change from integration is not bumped.')
    exit(1)


def _subprocess(args, **kwargs):
    print(f"RUN: {' '.join(args)}")
    response = subprocess.run(args, **kwargs, check=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    if response.stdout:
        print(f'RUN STDOUT:\n{response.stdout.decode("utf-8")}')
    if response.stderr:
        print(f'RUN STDERR:\n{response.stderr.decode("utf-8")}')
    print('\n')
    return response.stdout.decode('utf-8')


def check_diff(src, dst):
    """
    Check that there are no commits in the src branch that will be overwritten by rebasing on the dst.
    :param src: the source branch
    :param dst: the destination branch
    """
    result = _subprocess(['git', '--no-pager', 'log', '--graph', '--abbrev-commit', '--pretty=oneline',
                          '--no-merges', "--", f"{src}", f"^{dst}"])

    if result:
        print(f"Warning: the following commits are present on {dst} but not on {src}: \n{result}")
        if args.force:
            print(f"Warning: they will be overwritten on {dst} and discarded.")
        else:
            print(f"Warning: run with --force to overwrite and discard these commits from {dst}")
            exit(1)


def check_working_tree():
    """Check that are not changes in the current working tree before changing branches."""
    result = _subprocess(['git', '--no-pager', 'diff', '--ignore-submodules=untracked'])
    if result:
        print(result)
        print(f"Warning: Working tree contains changes to tracked files. Please commit or discard "
              f"your changes and try again.")
        exit(1)


def check_requirements():
    if _subprocess(['diff', '<(pip freeze)', f'<(tail -n +2 {os.environ["FUS_HOME"]}/requirements-dev.txt)']):
        if args.force:
            print(
                f"Warning: Your installed Python packages differ from requirements-dev.txt. Forcing deployment anyway.")
        else:
            print(f"Warning: Your installed Python packages differ from requirements-dev.txt. Please update your "
                  f"virtualenv. Run {args.prog} with --force to deploy anyway.")
            exit(1)


def make_release_notes(src, dst) -> str:
    """
    Produce release notes by retrieving the different commits from src to dst.
    :param src: the source branch
    :param dst: the destination branch
    :return:
    """
    result = _subprocess(['git', 'log', '--pretty=format:"%s"', f"origin/{src}...origin/{dst}"])
    commits = "\n".join([f"- {i[1:-1]}" for i in result.split("\n")])

    if args.release_notes:
        with open(args.release_notes, 'w') as f:
            f.write(commits)

    return commits


def commit(src, dst):
    print(_subprocess(['git', 'remote', 'set-url', 'origin',
                       f'https://{token}@github.com/{repo}.git']))
    print(_subprocess(['git', '-c', 'advice.detachedHead=false', 'checkout', f'origin/{src}']))
    print(_subprocess(['git', 'checkout', '-B', dst]))
    print(_subprocess(['git', 'push', '--force', 'origin', dst]))


def get_current_version(stage: str = None) -> str:
    "check the latest release from github"
    stage = stage if stage else args.stage
    version_url = f'https://api.github.com/repos/{repo}/releases'
    releases = requests.get(version_url).json()

    # would use version['target_commitish'] to grab the stage, but in use it grabs unexpected stages
    if releases and stage == 'integration':
        versions = [semver.parse_version_info(version['tag_name']) for version in releases
                    if semver.parse_version_info(version['tag_name']).prerelease
                    and semver.parse_version_info(version['tag_name']).prerelease.startswith('integration')]
    elif releases and stage == 'staging':
        versions = [semver.parse_version_info(version['tag_name']) for version in releases
                    if semver.parse_version_info(version['tag_name']).prerelease
                    and semver.parse_version_info(version['tag_name']).prerelease.startswith('rc')] \
                   or get_current_version('integration')
    elif releases and stage == 'prod':
        versions = [semver.parse_version_info(version['tag_name']) for version in releases
                    if not semver.parse_version_info(version['tag_name']).prerelease]
    if not versions:
        versions = [semver.VersionInfo(0, 0, 0)]
    return str(max(versions))


def update_version() -> str:
    """
    Retrieves the current version from github, bumps the version, and updates the values in service_config.json before
    committing to the dst branch
    :return: The new version.
    """
    cur_version = get_current_version(args.stage)

    if args.stage == "prod":
        prv_version = get_current_version(stage='staging')
        new_version = semver.finalize_version(prv_version)
    elif args.stage == "staging":
        prv_version = get_current_version(stage='integration')
        assert '-integration' in prv_version
        new_version = prv_version.replace('-integration', '-rc')  # don't bump the version number
    else:
        new_version = getattr(semver, f'bump_{args.release}')(str(cur_version))
        new_version = new_version if semver.parse_version_info(new_version).prerelease \
            else semver.bump_prerelease(new_version, token='integration')

    if cur_version == new_version:
        print("Nothing to promote")
        exit(0)
    else:
        print(f"Upgrading: {cur_version} -> {new_version}")
        return new_version


if __name__ == "__main__":
    release_map = {
        "integration": ("master", "integration", True),
        "staging": ("integration", "staging", True),
        "prod": ("staging", "prod", False)
    }

    token_path = os.environ.get('GITHUB_TOKEN_PATH')
    if token_path and token_path != 'None':
        with open(os.path.expanduser(token_path), 'r') as fp:
            token = fp.read().strip()
    else:
        secret_id = os.environ['GITHUB_TOKEN_SECRET_NAME']
        import boto3

        SM = boto3.client('secretsmanager')
        token = SM.get_secret_value(SecretId=secret_id)['SecretString']

    src, dst, prerelease = release_map[args.stage]
    dry_run = "(dry run)" if args.dry_run else ""
    print(f"Releasing {src} to {dst} {dry_run}")
    check_working_tree()
    check_diff(src, dst)
    release_notes = make_release_notes(src, dst)
    new_version = update_version()
    if not args.dry_run:
        old_branch = _subprocess(['git', 'rev-parse', f'origin/{dst}'])
        commit(src, dst)
        body = dict(
            tag_name=str(new_version),
            name="{dst} {new_version}".format(dst=dst, new_version=new_version),
            prerelease=prerelease,
            draft=False,
            target_commitish=dst,
            body=release_notes
        )

        resp = requests.post(
            f"https://api.github.com/repos/{repo}/releases",
            headers={"Authorization": f"token {token}"},
            data=json.dumps(body)
        )
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as ex:
            print(f"ERROR: Failed to create release!  Changes were:\n{release_notes}")
            print(f"Rolling back changes:")
            commit(old_branch, dst)
            raise ex
