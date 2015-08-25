#!/usr/bin/env python3
import gevent.monkey

gevent.monkey.patch_all()

import botocore
import collections
import connexion
import flask
import logging
import os
import requests
import scan
import threading
import time
import tokens

tokens.manage('tok', ['uid'])

# HTTP connection pooling
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
_session = requests.Session()
_session.mount('http://', adapter)
_session.mount('https://', adapter)
requests = _session


class BackgroundAccountThread(threading.Thread):
    def __init__(self, account_ids):
        threading.Thread.__init__(self, daemon=True)
        self.account_ids = account_ids

    def run(self):
        while True:
            try:
                for acc in self.account_ids:
                    for region in os.getenv('REGIONS').split(','):
                        for i in range(3):
                            try:
                                scan.update_connections(acc, region)
                                break
                            except botocore.exceptions.ClientError:
                                logging.exception('Client error')
                                # throttling
                                time.sleep(60)
            except:
                logging.exception('Failed to update')
            time.sleep(30)


class BackgroundThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        logging.info('Updating accounts..')
        scan.update_accounts()
        logging.info('Updating addresses..')
        scan.update_addresses()
        account_ids = collections.defaultdict(list)
        for acc in scan.ACCOUNTS:
            account_ids[hash(acc) % 16].append(acc)

        for ids in account_ids.values():
            thread = BackgroundAccountThread(ids)
            thread.start()


def get_health():
    return 'OK'


def get_addresses():
    q = flask.request.args.get('q')
    return {k: v for k, v in scan.NAMES.items() if not q or q in v}


def get_endpoints():
    res = {}
    for account_id, data in scan.ACCOUNTS.items():
        for region in data['regions']:
            res['/'.join((account_id, region))] = get_endpoints_by_account(account_id, region)
    return res


def get_endpoints_by_account(account_id, region):
    endpoints = set()
    for row in get_connections_by_account(account_id, region):
        endpoints.add((row['dest'], row['dest_port']))
    return list(endpoints)


def get_time(v):
    if v:
        return v.isoformat('T') + 'Z'


def get_accounts():
    return {k: {'name': v['name'], 'last_update': get_time(scan.LAST_TIMES.get(k))} for k, v in scan.ACCOUNTS.items()}


def get_account_connections():
    res = {}
    for key, connections in get_connections().items():
        counter = collections.Counter()
        for conn in connections:
            parts = conn['source'].split('/')
            if len(parts) >= 3:
                counter['/'.join(parts[:2])] += conn['score']
        res[key] = [{'source': k, 'score': v} for k, v in counter.items()]
    return res


def get_connections():
    res = {}
    for account_id, data in scan.ACCOUNTS.items():
        for region in data['regions']:
            res['/'.join((account_id, region))] = get_connections_by_account(account_id, region)
    return res


def get_connections_by_account(account_id, region):
    res = []
    day = None
    for conn, score in scan.get_stored_connections(account_id, region, day):
        src, dst = conn.split('->', 1)
        dst, dst_port = dst.rsplit(':', 1)
        dst_port = int(dst_port)
        res.append({'source': src, 'dest': dst, 'dest_port': dst_port, 'score': score})
    return res


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    logging.getLogger('botocore.vendored.requests.packages.urllib3.connectionpool').setLevel(logging.WARNING)
    # the following line is only needed for OAuth support
    api_args = {'tokeninfo_url': os.environ.get('HTTP_TOKENINFO_URL')}
    app = connexion.App(__name__, port=8080, debug=True, server='gevent')
    app.add_api('swagger.yaml', arguments=api_args)
    bg_thread = BackgroundThread()
    bg_thread.start()
    app.run()
