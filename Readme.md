# Fusillade

Fusillade (Federated User Identity Login & Access Decision Engine) is a service and library for managing user
authentication and authorization in federated services. Fusillade is built to be simple and to leverage well-known auth
protocols and standards together with existing global, scalable and supported IaaS APIs.

- The AuthN functionality in Fusillade consists of a login HTTPS endpoint that delegates user authentication to any
  configured [OpenID Connect](http://openid.net/connect/) compatible identity providers.
- The AuthZ part of Fusillade is
  an [ABAC](https://en.wikipedia.org/wiki/Attribute-based_access_control) [PDP](https://tools.ietf.org/html/rfc2904)
  (Policy Decision Point) API leveraging
  the [familiar syntax](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html) and reliable
  infrastructure of [AWS IAM](https://aws.amazon.com/iam/).

Together, these two subsystems provide an easy API for your application to answer the following questions:

- How do I instruct the user to log in?
- Who is the user performing this API request?
- Is this user authorized to perform action A on resource R?
- How do I delegate to the user an appropriately restricted ability to access cloud (IaaS) resources directly through
  IaaS (GCP, AWS) APIs?

To do this, your application should define an access control model consisting of the following:

- A list of trusted OIDC-compatible identity providers
- A naming schema for service actions (for example, `GetWidget`, `CreateFolder`, `DeleteAppointment`, `UpdateDocument`)
- A naming schema for resources in the following format: `arn:org-name:service-name:*:*:path/to/resource`
- A default policy assigned to new users, for example:

  ```json
  {
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "dss:CreateSubscription",
          "dss:UpdateSubscription",
          "dss:DeleteSubscription"
        ],
        "Resource": "arn:hca:dss:*:*:subscriptions/${user_id}/*"
      }
    ]
  }
  ```

## [WIP] [GA4GH AAI](https://github.com/ga4gh/data-security/tree/master/AAI) Compatibility
Fusillade will provide support for GA4GH Passport claims using the OIDC userinfo endpoint. A user can sign into 
multiple different identities and they will be linked together as the same user. Server side 
applications can view this information using the userinfo endpoint.

See https://github.com/HumanCellAtlas/fusillade/issues/307 for current progress.


## AWS Cloud Architecture

![AWS Cloud Architecture](https://www.lucidchart.com/publicSegments/view/b3470977-3924-4fb3-a07f-ce97be59dac1/image.png)

## Cloud Directory Structure

![Cloud Directory Structure](https://www.lucidchart.com/publicSegments/view/b08deb5a-881c-4eec-94af-9917f82d285f/image.png)

# Installing and configuring Fusillade

## Setup Environment

- pip install -r ./requirements-dev
- brew install jq
- brew install pandoc
- brew install moreutils
- brew install gettext
- brew link --force gettext 
- brew install terraform

- Setup [AWS CLI](https://github.com/aws/aws-cli) with the correct profile, default region, and output format.
- Local environment variables can be set in `environment.local` for convenience. If you use `source environment` and it 
  will set environment variables from `environment.local` after `environment` variables have been set, if you choose to 
  set them. If using multiple deployment with unique `environment.local` files, the `environment.local` file in the top
  directory of `fusillade` take precedence over `environment.local` in `fusillade/deployments/`
- Populate `FUS_ADMIN_EMAILS` with a list of admins to assigned upon creating the Fusillade deployment. This
  is only used when Fusillade is first deployed to create the first users. Afterwards this variable has no effect. If
  more admins are required, then assign a user the admin role.
- Deployment specific environment variables can be set in `./deployment/${FUS_DEPLOYMENT_STAGE}/environment.local` 
  per deployment for convenience.
- **Optionally** Before deploying Fusillade you can modify the [default policies and roles](../blob/master/policies) 
  to suit your needs. The `default_admin_role.json` is policy attached to the `fusillade_admin` role created during 
  deployment. The `default_group_policy.json` is assigned to all new group when they are created. The 
  `default_user_role.json` is the role assigned to the group `default_user` which is created during deployment. All of 
  these policies and role can be modified after deployment using the Fusillade API.

## Open ID Connect (OIDC) Provider Setup
The OIDC provide handle the OIDC authentication process. [Auth0](https://auth0.com/) is an example of an OIDC provider.
1. Set OPENID_PROVIDER in environment. This is the domain for the auth provider. 
1. Set **oauth2_config** in AWS Secrets Manager using `make set_oauth2_config`. **oauth2_config** contains the fields 
needed to proxy an OIDC provider. Populate this file with the OIDC providers you'd like to use to authenticate users. 
See [oauth2_config.json](../master/deployment/example/oauth2_config.example.json) for the expected format.
  
## Set Secrets

Fusillade uses AWS Secret Store for its secrets. You can set secrets using `./scripts/set_secret.py`. For example:

```bash
$ cat ./deployments/$(FUS_DEPLOYMENT_STAGE)/oauth2_config.json | ./scripts/set_secret.py --secret-name oauth2_config
```
 
 The following secrets are use by Fusillade:

* **oauth2_config** - see "OIDC Provider Setup" for more details.
* **test_service_accounts Optional** - contains google service accounts to test users access and admin access. This 
  only required for running tests See [test_service_accounts.json](../master/deployment/example/oauth2_config.example.json) 
  for the expected format.

## Set Parameter Stores

Upload parameter used in the lambdas to AWS SSM.

```bash
$ ./scripts/populate_lambda_ssm_parameters.py
```

Upload a file containing the environment variables used for a specific deployment to AWS SSM.  

```bash
$ ./scripts/populate_deployment_environment.py example --file ./deployments/example/environment.local
```

## Deploy Fusillade

Before running `make deploy`, populate your environment with the correct deployment variables from AWS SSM. You can run:

```bash
$ scripts/populate_deployment_environment.py example --print > environment.local
```

which will pull down the environment variables stored in `dcp/fusillade/{FUS_DEPLOYMENT_STAGE}/deployment_environment` 
in AWS SSM, and save it to `enviroment.local`. This environment will be used when you call:

```bash
$ make deploy
```

## Deploy Infrastructure 

Set `FUS_TERRAFORM_BACKEND_BUCKET_TEMPLATE` in your environment to an AWS S3 bucket to store your terraform state files.
run `make plan-infra` to verify what changes need to be made.
If you're ok with the changes run `make deploy-infra`.

### Environment Variables

- **`DEPLOYMENT`** - used to set the current deployment of Fusillade to target. This determines what deployment 
  variables to source from `environment`. 
- **`GITHUB_TOKEN_PATH`** - Point to the location of a file in your local directory containing a Github token used for 
  promoting Fusillade branches and publishing new version. If `GITHUB_TOKEN_SECRET_NAME` is also present, `GITHUB_TOKEN_PATH`
  will take precedence over `GITHUB_TOKEN_SECRET_NAME`.
- **`GITHUB_TOKEN_SECRET_NAME`** - Point to the location of an AWS parameters key containing a Github token used for 
  promoting Fusillade branches and publishing new version.
 
# Using Fusillade as a Service

The following are created on deployment:

* `/role/fusillade_admin` - contains a policy based on `default_admin_role.json`
* `/role/default_user` - contains a policy based on `default_user_role.json`
* `/user/{FUS_ADMIN_EMAILS}` - a user is created for each email in `FUS_ADMIN_EMAILS` and assigned 
  `/role/fusillade_admin`.
* `/group/user_default` - a group assigned to all users upon creation. It has the `/role/default_user` attached. Add 
  new roles to this group to apply that role to all users.
* `/user/public` -  a user for evaluating policies without an authenticated principle. `/user/public` is apart of 
  `/group/user_default`. Modify the roles attached to `/group/user_default` to modify what unauthenticated user can do.

**Note:** All of these resources can be modified using the Fusillade API after deployment.

**Note:** New `fusillade_admins` can be assigned using the Fusillade API and assigning the role of `fusillade_admin`
to a user.

## Users

A user can represent a service account, or a personal account. They can be explicitly created or created on demand when
a user's permissions are first evaluated. A user is automatically added to `/group/user_default` when created. All other
roles and groups must be added using the Fusillade API.

## Roles

Roles contains policies that are used to determine what a user can do. A role can either be directly applied to a 
user or indirectly applied to a user by applying the role to a group the user is a member.

## Groups

Groups are used to manage the roles attached to multiple users. 

## Policies

Policies can attached to a user, group, or role. The preferred method for attaching policies is to create a role with
that policy then attach that role to a group and assign users to that group. This makes it easier to manage many users
with fewer policies.
 
When the permissions of a user is evaluated, all policies attached to the user, the user's groups, and the user's roles
are used.
  
### Defining Policy

Uses [AWS IAM Policy grammar](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html) to 
define your services permissions.
For resource names use the same format as [AWS Service NameSpace](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html).

### Special Fusillade Context Keys for Policies

In the same way AWS IAM provides [context keys available to all services](https://docs.aws.amazon
.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-globally-available)
, Fusillade provides context keys that can be used in your policies.

- `fus:groups` - is a list of groups the current user belongs. This can be used to restrict permission based on 
  the group association
- `fus:roles` - is a list of roles the current user belongs. This can be used to restrict permission based on 
  the role association
- `fus:user_email` - is the email of the user. This can be used to restrict permission based on the users email.

## Specifics For DCP

The Fusillade staging environment should be used for developing other DCP components. For components using the 
Fusillade staging environment to test your dev environment, append all roles and groups created with `dev`. For example
For example `DSS_ADMIN` would be `DSS_ADMIN_DEV`. This is to prevent name collisions between dev and staging. 

**Note:** The Fusillade managed group `user_default` and user `public` will be modified for both your components 
staging and dev environment.

### Resource

For resource, set the `partition` to `hca`, set your `service` name to the name of your component, and set the 
`account-id` to the deployment stage. The field **resourcetype** can optionally be the name of a `resource_type` defined
 in fusillade. If `resourcetype` matches a `resource_type` defined in fusillade then a resource policy will be used to
 evaluate user access. All other fields can be used as needed or use \* for wild cards. Resource names are 
 case sensitive.
 
#### Examples

- arn:**hca**:**fusillade**:region:**dev**:**resourcetype**
- arn:**hca**:**dss**:region:**staging**:**resourcetype**/resource
- arn:**hca**:**query**:region:**integration**:**resourcetype**/resource/qualifier

#### Resource ACL 
A new `resource_type` is created by providing the name of the `resource_type`, and the actions that can be performed on it. 
 Once a `resource_type` is created you can store `resource_id`s of that `resource_type` to apply ACLs.
 
An `resource_policy` refers to a policy associated with a `resource_type` and is used to define different access levels 
 between principals and `resource_id`s. A principal may have only one level of access to a `resource_id`. All 
 `resource_id`s use the same pool of resource policies for that particular `resource_type`. This mean that modifying an
 `resource_policy`, modifies it for all principals with that access level to a `resource_id`. New `resource_policy` can
  be 
 defined for a `resource_type` after the `resource_type` has been created. Deleting an `resource_policy` removes access 
 for all principals with that level of access between a `resource_id`. `resource_policy` can only define policies that 
 use actions supported by that `resource_type`. Actions can be added and removed after a `resource_type` has been 
 created.
 
The creator of a `resource_id` is automatically designated as the owner of the resource. The owner of a
 `resource_id` can add additional owners, and assign access levels to principals for that `resource_id`. A principal only 
 has access to resource they are give access to, either directly or through group membership.

If a `resource_type` is deleted, all `resource_policy` and 
 `resource_id`s associated with that type are deleted.
 
# Using Fusillade as a library

# Using Fusillade as a proxy

# Bundling native cloud credentials

### AWS

### GCP

# Service access control

To use Fusillade, your service must itself be authenticated and authorized. The access control model for this depends on
how you're using Fusillade.

### Library - Cooperative model

When using Fusillade as a library, your application's AWS IAM role is also your Fusillade access role. The library uses
AWS Cloud Directory and AWS IAM using your application's IAM credentials. (TODO: add links for ACD/IAM IAM and show
sample policy)

### Service - Enforced model

When using Fusillade as a service, your application is itself subject to an IAM policy governing its ability to read and
write permissions data. The Fusillade service administrator configures the Fusillade policy governing this in the
service configuration.

# How To

## Run Tests

1. Set up the AWS command line utility to link it to the correct AWS account.
1. Clone a local copy of the repository
1. Install software required for development using `pip install -r requirements-dev.txt`
1. Set environment variables using the command `source ./environment`
1. Run tests by running `make test`

## Upgrade Cloud Directory Schema

1. Run `make check_directory_schema` to check if your local schema matches the published schema.
1. If the published schema does not match your local, run `make upgrade_directory_schema`.

## Links

* [Project home page (GitHub)](https://github.com/HumanCellAtlas/fusillade)
* [Documentation (Read the Docs)](https://fusillade.readthedocs.io/)
* [Package distribution (PyPI)](https://pypi.python.org/pypi/fusillade)

# Bugs

Please report bugs, issues, feature requests, etc. on [GitHub](https://github.com/HumanCellAtlas/fusillade/issues).

# License

Licensed under the terms of the [MIT License](https://opensource.org/licenses/MIT).

[![Travis CI](https://travis-ci.org/HumanCellAtlas/fusillade.svg)](https://travis-ci.org/HumanCellAtlas/fusillade)
[![PyPI version](https://img.shields.io/pypi/v/fusillade.svg)](https://pypi.python.org/pypi/fusillade)
[![PyPI license](https://img.shields.io/pypi/l/fusillade.svg)](https://pypi.python.org/pypi/fusillade)
[![Read The Docs](https://readthedocs.org/projects/fusillade/badge/?version=latest)](https://pypi.python.org/pypi/fusillade)
[![Known Vulnerabilities](https://snyk.io/test/github/HumanCellAtlas/fusillade/badge.svg)](https://snyk.io/test/github/HumanCellAtlas/fusillade)
[![Build Status](https://travis-ci.com/HumanCellAtlas/fusillade.svg?branch=master)](https://travis-ci.com/HumanCellAtlas/fusillade)
[![codecov](https://codecov.io/gh/HumanCellAtlas/fusillade/branch/master/graph/badge.svg)](https://codecov.io/gh/HumanCellAtlas/fusillade)
