#!/usr/bin/env python3
import click
import logging
import requests
import zign.api

from clickclick import secho
from queue import Queue
from threading import Thread

TIMEOUT = 10  # seconds


class Worker(Thread):

    """Thread executing tasks from a given tasks queue"""

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                logging.exception('Exception in %s(%s, %s): %s', func, args, kargs, e)
            self.tasks.task_done()


class ThreadPool:

    """Pool of threads consuming tasks from a queue"""

    def __init__(self, num_threads):
        self.num_tasks = 0
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        """Add a task to the queue"""

        self.tasks.put((func, args, kargs))
        self.num_tasks += 1

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""

        self.tasks.join()


SSL_PORTS = set([443, 8443])


def check_endpoint(account, endpoint, port, show_public_only):
    if port in SSL_PORTS:
        scheme = 'https'
    else:
        scheme = 'http'
    url = '{}://{}:{}/'.format(scheme, endpoint.split('/')[-1], port)
    try:
        r = requests.get(url, timeout=5, verify=False)
        do_print = True
        if r.status_code == 401:
            style = {'fg': 'green', 'bold': True}
            if show_public_only:
                do_print = False
        else:
            style = {'fg': 'yellow', 'bold': True}
        if do_print:
            secho('{} {} {} {}'.format(account, url, r.status_code, r.text.strip().replace('\n', ' ')[:40]), **style)
    except Exception as e:
        if not show_public_only:
            secho('{} {} {}'.format(account, url, str(e)[:40]))

requests.packages.urllib3.disable_warnings()


@click.command()
@click.argument('url')
@click.option('--show-public-only', is_flag=True)
def scan_endpoints(url, show_public_only):
    access_token = zign.api.get_token('connection-tracker', ['uid'])

    r = requests.get(url + '/endpoints', headers={'Authorization': 'Bearer {}'.format(access_token)})
    data = r.json()

    pool = ThreadPool(32)

    for account, public_endpoints in sorted(data.items()):
        for endpoint in public_endpoints:
            pool.add_task(check_endpoint, account, endpoint['dest'], endpoint['dest_port'], show_public_only)

    pool.wait_completion()

if __name__ == '__main__':
    scan_endpoints()
