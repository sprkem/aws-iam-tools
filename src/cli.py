import click
from prettytable import PrettyTable

from src import iam

@click.group()
def cli():
    pass

@cli.command()
@click.option('--permission', '-p', multiple=True)
def search(permission):
    results = iam.search_for_permissions(permission)

    for permission in results:
        table = PrettyTable()
        table.field_names = ['Permission', 'Principal', 'Type', 'Allow Type', 'Allowed By']

        for r in results[permission]:
            table.add_row([permission, r['Principal'], r['Type'], r['AllowType'], r['Policy']])

        print(table)

if __name__ == '__main__':
    cli()