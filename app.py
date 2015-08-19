#!/usr/bin/env python3
import gevent.monkey

gevent.monkey.patch_all()

import botocore
import collections
import connexion
import datetime
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
                    for region in ['eu-west-1']:
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
            account_ids[hash(acc) % 64].append(acc)

        for ids in account_ids.values():
            thread = BackgroundAccountThread(ids)
            thread.start()


def get_accounts():
    return scan.ACCOUNTS


def get_connections():
    res = {}
    for key, val in scan.CONNECTIONS.items():
        res['/'.join(key)] = get_connections_by_account(key[0], key[1])
    return res


def get_connections_by_account(account_id, region):
    scan.REQUESTED_ACCOUNTS.add((account_id, region))
    res = []
    for conn, count in scan.CONNECTIONS.get((account_id, region), collections.Counter()).most_common():
        res.append(list(conn) + [count])
    return res


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    # the following line is only needed for OAuth support
    api_args = {'tokeninfo_url': os.environ.get('HTTP_TOKENINFO_URL')}
    app = connexion.App(__name__, port=8080, debug=True, server='gevent')
    app.add_api('swagger.yaml', arguments=api_args)
    bg_thread = BackgroundThread()
    bg_thread.start()
    app.run()
