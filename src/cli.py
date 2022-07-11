import click
from prettytable import PrettyTable

from src import iam


@click.group()
def cli():
    pass


@cli.command()
@click.option('--permission', '-p', multiple=True)
@click.option('--profile')
@click.option('--output',
              type=click.Choice(['PrettyTable', 'csv'], case_sensitive=False))
def search(permission, profile, output):
    output = output if output else 'PrettyTable'

    results = iam.search_for_permissions(permission, profile)

    fields = ['Principal',
              'Type', 'Allow Type', 'Allowed By', 'Trust']

    if output == 'PrettyTable':
        print_search_as_pt(results, fields)
    elif output == 'csv':
        print_search_as_csv(results, fields)


def print_search_as_pt(results, fields):
    for permission in results:
        table = PrettyTable()
        print(permission)
        table.field_names = fields

        for r in results[permission]:
            table.add_row([r['Principal'],
                          r['Type'], r['AllowType'], r['Policy'], r.get('Trust', 'N/A')])

        print(table)


def print_search_as_csv(results, fields):
    for permission in results:
        header = [permission] + fields
        print(','.join(header))

        for r in results[permission]:
            row = [permission, r['Principal'],
                   r['Type'], r['AllowType'], r['Policy'], r.get('Trust', 'N/A')]
            print(','.join(row))


if __name__ == '__main__':
    cli()
