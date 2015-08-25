==================
Connection Tracker
==================

Hack to find public endpoints and connections from non-private IPs.

This app can be deployed in one account and will read the VPC Flow Logs of all configured AWS accounts to find inbound connections (packets) to public endpoints (ELB, Elastic IPs, RDS, ..).


.. code-block:: bash

    $ sudo pip3 install -r requirements.txt # install dependencies
    $ export HTTP_TEAM_SERVICE_URL=https://teams.example.org
    $ export OAUTH2_ACCESS_TOKENS=tok=$(zign tok -n test)
    $ export DOMAIN={account_name}.example.org
    $ export REGIONS=eu-west-1
    $ export NETWORKS=my_office=123.123.123.0/24,some_nat=456.789.1.1/32
    $ export REDIS_HOST=my-redis-host.example.org
    $ ./app.py

Features
========

* Read deltas from multiple VPC Flow Logs (multiple AWS accounts) in "parallel" (using gevent greenlets)
* Resolve DNS names for ELBs, public EC2 instances and RDS clusters
* Update simple internal dict with counter values
* Provide HTTP interface to retrieve inbound connections, endpoints and resolved addresses
* Stores connection information in Redis

Examples
========

Some example JSON results (from service running on localhost port 8080):

``GET /accounts``

.. code-block:: json

    {
        "123456789123": {
            "last_update": "2015-08-24T16:33:01.864301Z",
            "name": "myaccount"
        },
        "987654321001": {
            "last_update": "2015-08-24T16:37:09.909320Z",
            "name": "foobar"
        },
    }


``GET /connections``

.. code-block:: json

    {
        "123456789123/eu-west-1": [
            {
                "source": "987654321001/eu-west-1/nat-eu-west-1b.foobar.example.org",
                "dest": "myapp-1-123.eu-west-1.elb.amazonaws.com",
                "dest_port": 443,
                "score": 2
            },
            {
                "source": "987654321001/eu-west-1/nat-eu-west-1a.foobar.example.org",
                "dest": "hello-world-2-456.eu-west-1.elb.amazonaws.com",
                "dest_port": 443,
                "score": 1
            }
        ]
    }

The connections JSON will return a list of dictionaries for each AWS account containing:

* source name (prefixed with account ID and region for known VPCs)
* destination name (e.g. ELB or RDS DNS name)
* destination TCP port
* score/counter (number of matching records from VPC Flow Logs)


Helpers
=======

.. code-block:: bash

    $ ./scan-endpoints.py https://connection-tracker.example.org
