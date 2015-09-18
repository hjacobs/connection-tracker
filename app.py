#!/usr/bin/env python3
import botocore
import collections
import connexion
import flask
import logging
import os
import requests
import scan
import time
import tokens

tokens.manage('tok', ['uid'])

# HTTP connection pooling
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
_session = requests.Session()
_session.mount('http://', adapter)
_session.mount('https://', adapter)
requests = _session


def get_health():
    return 'OK'


def get_metrics():
    import uwsgi_metrics
    return uwsgi_metrics.view()


def get_addresses():
    scan.update_addresses()
    q = flask.request.args.get('q')
    return {k: v for k, v in scan.NAMES.items() if not q or (v and q in v)}


def get_endpoints(date=None):
    scan.update_accounts()
    if not date:
        date = flask.request.args.get('date')
    res = {}
    for account_id, data in scan.ACCOUNTS.items():
        for region in data['regions']:
            res['/'.join((account_id, region))] = get_endpoints_by_account(account_id, region, date)
    return res


def get_endpoints_by_account(account_id, region, date=None):
    if not date:
        date = flask.request.args.get('date')
    endpoints = set()
    for row in get_connections_by_account(account_id, region, date):
        endpoints.add((row['dest'], row['dest_port']))
    return list([{'dest': e[0], 'dest_port': e[1]} for e in endpoints])


def get_time(v):
    if v:
        return v.isoformat('T') + 'Z'


def get_accounts():
    scan.update_accounts()
    return {k: {'name': v['name'], 'last_update': get_time(scan.get_last_update(k, v['regions'][0]))}
            for k, v in scan.ACCOUNTS.items()}


def get_account_connections(date=None):
    if not date:
        date = flask.request.args.get('date')
    include = set(flask.request.args.get('include', '').split(','))
    res = {}
    for key, connections in get_connections(date).items():
        counter = collections.Counter()
        for conn in connections:
            if include and conn['source'] in include:
                counter[conn['source']] += conn['score']
            else:
                parts = conn['source'].split('/')
                if len(parts) >= 3:
                    counter['/'.join(parts[:2])] += conn['score']
        res[key] = [{'source': k, 'score': v} for k, v in counter.items()]
    return res


def get_connections(date=None):
    scan.update_accounts()
    if not date:
        date = flask.request.args.get('date')
    res = {}
    for account_id, data in scan.ACCOUNTS.items():
        for region in data['regions']:
            res['/'.join((account_id, region))] = get_connections_by_account(account_id, region, date)
    return res


def get_connections_by_account(account_id, region, date=None):
    res = []
    if not date:
        date = flask.request.args.get('date')
    for conn, score in scan.get_stored_connections(account_id, region, date):
        src, dst = conn.split('->', 1)
        dst, dst_port = dst.rsplit(':', 1)
        dst_port = int(dst_port)
        res.append({'source': src, 'dest': dst, 'dest_port': dst_port, 'score': score})
    return res


PARALLEL = 8


def run_update(signum):
    if uwsgi.is_locked(signum):
        return
    uwsgi.lock(signum)
    try:
        while True:
            try:
                logging.info('Updating accounts..')
                scan.update_accounts()
                logging.info('Updating addresses..')
                scan.update_addresses()
                break
            except:
                logging.exception('Failed to update accounts/addresses, retrying')
                time.sleep(30)

        for i in range(100):
            try:
                for acc in scan.ACCOUNTS:
                    if hash(acc) % PARALLEL == signum-1:
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
            time.sleep(60)
    finally:
        uwsgi.unlock(signum)


logging.basicConfig(level=logging.INFO)

logging.getLogger('botocore.vendored.requests.packages.urllib3.connectionpool').setLevel(logging.WARNING)
# the following line is only needed for OAuth support
api_args = {'tokeninfo_url': os.environ.get('HTTP_TOKENINFO_URL')}
app = connexion.App(__name__, port=8080)
app.add_api('swagger.yaml', arguments=api_args)
application = app.app

try:
    import uwsgi
    for i in range(1, 1 + PARALLEL):
        signum = i
        uwsgi.register_signal(signum, "", run_update)
        uwsgi.add_timer(signum, 10)

    import uwsgi_metrics
    uwsgi_metrics.initialize()
except Exception as e:
    print(e)

if __name__ == '__main__':
    app.run()
