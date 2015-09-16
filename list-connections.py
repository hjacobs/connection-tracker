#!/usr/bin/env python3
import click
import datetime
import requests
import zign.api

from clickclick import print_table, OutputFormat

requests.packages.urllib3.disable_warnings()

output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')


@click.command()
@click.argument('url')
@click.option('--suspicious', is_flag=True)
@click.option('--date-from')
@click.option('--date-to')
@output_option
def cli(url, suspicious, date_from, date_to, output):
    token = zign.api.get_existing_token('test')
    if token is None:
        print("Token 'test' expired")
        exit(1)

    if date_from:
        date_from = datetime.datetime.strptime(date_from, '%Y-%m-%d')
    else:
        date_from = datetime.datetime.utcnow()

    if date_to:
        date_to = datetime.datetime.strptime(date_to, '%Y-%m-%d')
    else:
        date_to = datetime.datetime.utcnow()

    access_token = token['access_token']

    r = requests.get(url + '/accounts', headers={'Authorization': 'Bearer {}'.format(access_token)})
    r.raise_for_status()
    accounts = r.json()

    rows = []
    date = date_from
    while date.date() <= date_to.date():
        params = {}
        params['date'] = date.strftime('%Y-%m-%d')
        r = requests.get(url + '/connections', headers={'Authorization': 'Bearer {}'.format(access_token)},
                         params=params)
        r.raise_for_status()
        data = r.json()

        for account, connections in sorted(data.items()):
            for conn in connections:
                account_id, region = account.split('/')
                conn['account_id'] = account_id
                conn['account_name'] = accounts.get(account_id, {}).get('name')
                conn['region'] = region
                if not suspicious or conn['dest_port'] != 443:
                    rows.append(conn)
        date += datetime.timedelta(days=1)
    rows.sort(key=lambda r: (r['account_id'], r['account_name'], r['region'], r['dest'], r['dest_port']))
    with OutputFormat(output):
        print_table('account_id account_name region dest dest_port source score'.split(), rows)


if __name__ == '__main__':
    cli()
