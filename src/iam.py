
import boto3
import multiprocessing
from collections import defaultdict


def search_for_permissions(permissions):
    # print(permissions)
    client = boto3.client('iam')

    data_map = {
        'policies': {
            'managed': {},
            'inline': {},
        },
        'matches': defaultdict(list)
    }

    for permission in permissions:
        data_map['matches'][permission] = []

    # search roles
    roles = get_roles(client)
    search_roles(roles, permissions, data_map)

    # search users
    users = get_users(client)
    search_users(users, permissions, data_map)

    # search groups
    groups = get_groups(client)
    search_groups(groups, permissions, data_map)

    return data_map['matches']


def get_roles(client):
    roles = []

    paginator = client.get_paginator('list_roles')

    page_iterator = paginator.paginate()

    for page in page_iterator:
        roles.extend([x['RoleName'] for x in page['Roles']])

    return roles


def get_inline_policies(client, principal_name, type):
    policies = []

    if type == 'role':
        op = 'list_role_policies'
        arg_name = 'RoleName'
    elif type == 'user':
        op = 'list_user_policies'
        arg_name = 'UserName'
    if type == 'group':
        op = 'list_group_policies'
        arg_name = 'GroupName'

    args = {arg_name: principal_name}

    paginator = client.get_paginator(op)

    page_iterator = paginator.paginate(**args)

    for page in page_iterator:
        policies.extend([x for x in page['PolicyNames']])

    return policies


def get_policy(client, principal_name, policy, type):

    if type == 'role':
        response = client.get_role_policy(
            RoleName=principal_name, PolicyName=policy)
    elif type == 'user':
        response = client.get_user_policy(
            UserName=principal_name, PolicyName=policy)
    if type == 'group':
        response = client.get_group_policy(
            GroupName=principal_name, PolicyName=policy)

    return response['PolicyDocument']


def get_attached_policies(client, principal_name, type):
    policies = []

    if type == 'role':
        op = 'list_attached_role_policies'
        arg_name = 'RoleName'
    elif type == 'user':
        op = 'list_attached_user_policies'
        arg_name = 'UserName'
    if type == 'group':
        op = 'list_attached_group_policies'
        arg_name = 'GroupName'

    args = {arg_name: principal_name}

    paginator = client.get_paginator(op)

    page_iterator = paginator.paginate(**args)

    for page in page_iterator:
        policies.extend([x['PolicyArn'] for x in page['AttachedPolicies']])

    return policies


def search_role(role, permissions, data_map):
    client = boto3.client('iam')

    matches = defaultdict(list)

    inline_policies = get_inline_policies(
        client, principal_name=role, type='role')  # this is list of names
    managed_policies = get_attached_policies(
        client, principal_name=role, type='role')  # this is list of arns

    for policy in inline_policies:

        policy_data = get_policy(
            client, principal_name=role, policy=policy, type='role')

        for permission in permissions:
            if statement_allows_permissions(policy_data, permission):
                matches[permission].append({
                    'AllowType': 'Inline Policy',
                    'Policy': policy,
                    'Type': 'Role',
                    'Principal': role
                })

    for policy_arn in managed_policies:
        if policy_arn not in data_map['policies']['managed']:
            data_map['policies']['managed'][policy_arn] = get_managed_policy(
                client, policy_arn)

        policy_data = data_map['policies']['managed'].get(policy_arn)

        for permission in permissions:
            if statement_allows_permissions(policy_data, permission):
                matches[permission].append({
                    'AllowType': 'Managed Policy',
                    'Policy': policy_arn,
                    'Type': 'Role',
                    'Principal': role
                })

    return matches


def search_roles(roles, permissions, data_map):
    star_args = []
    for role in roles:
        star_args.append((role, permissions, data_map))

    with multiprocessing.Pool() as pool:
        results = pool.starmap(search_role, star_args)
        for result in results:
            for permission in result:
                data_map['matches'][permission].extend(result[permission])


def get_users(client):
    users = []

    paginator = client.get_paginator('list_users')

    page_iterator = paginator.paginate()

    for page in page_iterator:
        users.extend([x['UserName'] for x in page['Users']])

    return users


def search_users(users, permissions, data_map):
    star_args = []
    for user in users:
        star_args.append((user, permissions, data_map))

    with multiprocessing.Pool() as pool:
        results = pool.starmap(search_user, star_args)
        for result in results:
            for permission in result:
                data_map['matches'][permission].extend(result[permission])


def search_user(user, permissions, data_map):
    client = boto3.client('iam')

    matches = defaultdict(list)

    inline_policies = get_inline_policies(
        client, principal_name=user, type='user')  # this is list of names
    managed_policies = get_attached_policies(
        client, principal_name=user, type='user')  # this is list of arns

    for policy in inline_policies:
        policy_data = get_policy(
            client, principal_name=user, policy=policy, type='user')

        for permission in permissions:
            if statement_allows_permissions(policy_data, permission):
                matches[permission].append({
                    'AllowType': 'Inline Policy',
                    'Policy': policy,
                    'Type': 'User',
                    'Principal': user
                })

    for policy_arn in managed_policies:
        if policy_arn not in data_map['policies']['managed']:
            data_map['policies']['managed'][policy_arn] = get_managed_policy(
                client, policy_arn)

        policy_data = data_map['policies']['managed'].get(policy_arn)

        for permission in permissions:
            if statement_allows_permissions(policy_data, permission):
                matches[permission].append({
                    'AllowType': 'Managed Policy',
                    'Policy': policy_arn,
                    'Type': 'User',
                    'Principal': user
                })

    return matches


def get_groups(client):
    groups = []

    paginator = client.get_paginator('list_groups')

    page_iterator = paginator.paginate()

    for page in page_iterator:
        groups.extend([x['GroupName'] for x in page['Groups']])

    return groups


def search_groups(groups, permissions, data_map):
    star_args = []
    for group in groups:
        star_args.append((group, permissions, data_map))

    with multiprocessing.Pool() as pool:
        results = pool.starmap(search_group, star_args)
        for result in results:
            for permission in result:
                data_map['matches'][permission].extend(result[permission])


def search_group(group, permissions, data_map):
    client = boto3.client('iam')

    matches = defaultdict(list)

    inline_policies = get_inline_policies(
        client, principal_name=group, type='group')  # this is list of names
    managed_policies = get_attached_policies(
        client, principal_name=group, type='group')  # this is list of arns

    for policy in inline_policies:
        policy_data = get_policy(
            client, principal_name=group, policy=policy, type='group')

        for permission in permissions:
            if statement_allows_permissions(policy_data, permission):
                matches[permission].append({
                    'AllowType': 'Inline Policy',
                    'Policy': policy,
                    'Type': 'Group',
                    'Principal': group
                })

    for policy_arn in managed_policies:
        if policy_arn not in data_map['policies']['managed']:
            data_map['policies']['managed'][policy_arn] = get_managed_policy(
                client, policy_arn)

        policy_data = data_map['policies']['managed'].get(policy_arn)

        for permission in permissions:
            if statement_allows_permissions(policy_data, permission):
                matches[permission].append({
                    'AllowType': 'Managed Policy',
                    'Policy': policy_arn,
                    'Type': 'Group',
                    'Principal': group
                })

    return matches


def get_managed_policy(client, policy_arn):
    response = client.get_policy(
        PolicyArn=policy_arn
    )

    default_version = response['Policy']['DefaultVersionId']

    response = client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=default_version
    )

    return response['PolicyVersion']['Document']


def statement_allows_permissions(document, permission):
    for statement in document['Statement']:
        if statement['Effect'] != 'Allow':
            continue

        if 'Action' not in statement:
            continue

        if isinstance(statement['Action'], str):
            return action_allows_permission(statement['Action'], permission)
        else:
            for action in statement['Action']:
                if action_allows_permission(action, permission):
                    return True

    return False


def action_allows_permission(action, permission):

    if action == '*':
        return True

    if action == permission:
        return True

    a1, a2 = action.split(':')
    b1, b2 = permission.split(':')

    # e.g. iam:* allows iam:PassRole
    if a1 == b1 and a2 == '*':
        return True

    return False
