#!/usr/bin/env python
"""
A tool for promoting server code to different stages of productions, and minting new releases in github.

In order to release you must have a github access token with permissions to write to your repository. Set
environment variable `GITHUB_TOKEN_PATH` to the path of a file which contains github access token, or set environment
variable `GITHUB_TOKEN_SECRET_NAME` to the path of the AWS secret which contains github access token.

`./promote.py integration` promotes master to integration and creates a prerelease in github.
`./promote.py staging` promotes integration to staging and creates a prerelease in github.
`./promote.py production` promotes staging to production and creates a release in github.

Versioning follows https://semver.org/ standard
"""
import argparse
import json
import os
import subprocess
import tempfile

import requests
import semver

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('stage',
                    metavar='stage',
                    type=str,
                    help="The stage you would like to create a release to.",
                    choices=["integration", "staging", "production"])
parser.add_argument('--release', '-r',
                    type=str,
                    choices=["major", "minor", "patch", "prerelease", "build"],
                    default=None,
                    required=False,
                    help="The type of release to produce.")
parser.add_argument('--force', '-f',
                    action="store_true")
parser.add_argument('--release-notes', type=str, required=False,
                    help="The path to a text file containing the release "
                         "notes.",
                    )
parser.add_argument('--dry-run', '-d',
                    action="store_true")
parser.add_argument('--auto', action="store_false",
                    help="Used for automated deployment. No user interaction is required.")
args = parser.parse_args()


def _subprocess(args, **kwargs) -> str:
    print(f"RUN: {' '.join(args)}")
    return subprocess.run(args, **kwargs, check=True, stdout=subprocess.PIPE).stdout.decode('utf-8')


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
    produce release notes by retrieving the different commits from src to dst.
    :param src: the source branch
    :param dst: the destination branch
    :return:
    """
    if args.release_notes:
        subprocess.call([os.environ.get('EDITOR', 'vim'), args.release_notes])
        with open(args.release_notes, 'r') as file:
            r_notes = file.read()
    else:
        result = _subprocess(['git', 'log', '--pretty=format:"%s"', f"{src}...{dst}"])
        r_notes = "\n".join([f"- {i[1:-1]}" for i in result.split("\n")])
        if args.auto:
            with tempfile.TemporaryDirectory() as temp_path:
                temp_file = f"{temp_path}/release_notes.txt"
                with open(temp_file, 'w') as file:
                    file.write(r_notes)
                    subprocess.call([os.environ.get('EDITOR', 'vim'), temp_file])
                with open(temp_file, 'r') as file:
                    r_notes = file.read()
    return r_notes


def commit(src, dst):
    print(_subprocess(['git', 'fetch', '--all']))
    print(_subprocess(['git', '-c', 'advice.detachedHead=false', 'checkout', f'origin/{src}']))
    print(_subprocess(['git', 'checkout', '-B', dst]))
    print(_subprocess(['git', 'push', '--force', 'origin', dst]))


def get_current_version() -> semver.VersionInfo:
    "check the latest release from github"
    releases = s.get("https://api.github.com/repos/HumancellAtlas/fusillade/releases").json()
    if releases:
        latest_version = max([semver.parse_version_info(version['tag_name']) for version in releases])
    else:
        latest_version = semver.VersionInfo(0, 0, 0)
    return latest_version


def update_version() -> str:
    """
    Retrieves the current version from github, bumps the version, and updates the values in service_config.json before
    committing to the dst branch
    :return: the new version./
    """
    new_version = cur_version = get_current_version()
    if args.release:
        new_version = getattr(semver, f'bump_{args.release}')(str(new_version))
    if args.stage == "production":
        new_version = semver.finalize_version(str(new_version))
    else:
        new_version = str(semver.bump_prerelease(str(new_version), token=args.stage))
    print(f"Upgrading: {cur_version} -> {new_version}")
    return new_version


Release_msg = "Releasing {src} to {dst}"
if args.dry_run:
    Release_msg = Release_msg + " (dry run)"
Release_name = "{dst} {new_version}"
release_map = {
    "integration": ("master", "integration", True),
    "staging": ("integration", "staging", True),
    "production": ("staging", "production", False)
}

s = requests.Session()
token_path = os.environ.get('GITHUB_TOKEN_PATH')
if token_path:
    with open(os.path.expanduser(token_path), 'r') as fp:
        token = fp.read().strip()
else:
    secret_id = os.environ['GITHUB_TOKEN_SECRET_NAME']
    import boto3

    SM = boto3.client('secretsmanager')
    token = SM.get_secret(SecretId=secret_id)['SecretString']

if __name__ == "__main__":
    src, dst, prerelease = release_map[args.stage]
    print(Release_msg.format(src=src, dst=dst))
    check_working_tree()
    check_diff(src, dst)
    release_notes = make_release_notes(src, dst)
    new_version = update_version()
    if not args.dry_run:
        commit(src, dst)
        name = Release_name.format(dst=dst, new_version=new_version)
        body = dict(
            tag_name=str(new_version),
            name=name,
            prerelease=prerelease,
            draft=False,
            target_commitish=dst,
            body=release_notes
        )
        resp = s.post(
            f"https://api.github.com/repos/HumancellAtlas/fusillade/releases",
            headers={"Authorization": f"token {token}"},
            data=json.dumps(body)
        )
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as ex:
            with open(f"release notes for {name}.txt", 'w') as fp:
                fp.write(release_notes)
            print("ERROR: Failed to create release!")
            raise ex
