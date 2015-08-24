#!/usr/bin/env python3
import logging
import requests
import sys
import zign.api

from clickclick import ok, warning
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


def check_endpoint(account, endpoint, port):
    if port in SSL_PORTS:
        scheme = 'https'
    else:
        scheme = 'http'
    url = '{}://{}:{}/'.format(scheme, endpoint.split('/')[-1], port)
    try:
        r = requests.get(url, timeout=5, verify=False)
        if r.status_code == 401:
            ok('{} {} {} {}'.format(account, endpoint, port, r.status_code))
        else:
            warning('{} {} {} {}'.format(account, endpoint, port, r.status_code))
    except Exception as e:
        print(account, endpoint, port, str(e))

requests.packages.urllib3.disable_warnings()

url = sys.argv[1]

token = zign.api.get_existing_token('test')
access_token = token['access_token']

r = requests.get(url + '/endpoints', headers={'Authorization': 'Bearer {}'.format(access_token)})
data = r.json()

pool = ThreadPool(32)

for account, public_endpoints in sorted(data.items()):
    for endpoint, port in public_endpoints:
        pool.add_task(check_endpoint, account, endpoint, port)

pool.wait_completion()

