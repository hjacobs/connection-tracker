#!/usr/bin/env python3
import click
import requests
import zign.api

from graphviz import Digraph


@click.command()
@click.argument('url')
@click.option('--include', help='include additional sites/networks')
def cli(url, include):
    access_token = zign.api.get_token('connection-tracker', ['uid'])

    r = requests.get(url + '/accounts', headers={'Authorization': 'Bearer {}'.format(access_token)})
    accounts = r.json()

    def get_label(account_region):
        parts = account_region.split('/')
        name = accounts.get(parts[0], {}).get('name', parts[0])
        return name

    r = requests.get(url + '/account-connections',
                     params={'include': include},
                     headers={'Authorization': 'Bearer {}'.format(access_token)}, timeout=180)
    data = r.json()
    max_score = 0
    for dest, sources in data.items():
        for row in sources:
            if row['score'] > max_score:
                max_score = row['score']

    graph = Digraph(comment='Account Graph', engine='circo', format='svg')
    for dest, sources in data.items():
        graph.node(dest, label=get_label(dest), style='filled')
        for row in sources:
            source = row['source']
            graph.node(source, label=get_label(source), style='filled')
            graph.edge(source, dest, weight=str(int(row['score'])), penwidth=str(max(0.5, 5 * row['score']/max_score)))

    graph.render('account-graph')

if __name__ == '__main__':
    cli()
