#!/usr/bin/env python3
import click
import requests
import zign.api

from clickclick import print_table

requests.packages.urllib3.disable_warnings()


@click.command()
@click.argument('url')
@click.option('--suspicious', is_flag=True)
def cli(url, suspicious):
    token = zign.api.get_existing_token('test')
    access_token = token['access_token']

    r = requests.get(url + '/accounts', headers={'Authorization': 'Bearer {}'.format(access_token)})
    accounts = r.json()

    r = requests.get(url + '/connections', headers={'Authorization': 'Bearer {}'.format(access_token)})
    data = r.json()

    rows = []
    for account, connections in sorted(data.items()):
        for conn in connections:
            account_id, region = account.split('/')
            conn['account_id'] = account_id
            conn['account_name'] = accounts.get(account_id, {}).get('name')
            conn['region'] = region
            if not suspicious or conn['dest_port'] != 443:
                rows.append(conn)
    print_table('account_id account_name region dest dest_port source score'.split(), rows)


if __name__ == '__main__':
    cli()
