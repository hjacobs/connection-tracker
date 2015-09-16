==================
Connection Tracker
==================

Hack to find public endpoints and connections from non-private IPs.

This app can be deployed in one account and will read the VPC Flow Logs of all configured AWS accounts to find inbound connections (packets) to public endpoints (ELB, Elastic IPs, RDS, ..).

Please note that the Connection Tracker is not a comprehensive security checker, it will only list information found via VPC Flow Logs!


.. code-block:: bash

    $ sudo pip3 install -r requirements.txt                     # install Python dependencies
    $ export HTTP_TEAM_SERVICE_URL=https://teams.example.org    # Team Service URL to return account IDs and names
    $ export OAUTH2_ACCESS_TOKENS=tok=$(zign tok -n test)       # needed to query Team Service
    $ export DOMAIN={account_name}.example.org                  # domain template for each AWS account
    $ export REGIONS=eu-west-1                                  # regions to scan
    $ export NETWORKS=my_office=1.2.3.0/24,some_nat=4.5.6.1/32  # optional named network IP ranges
    $ export REDIS_HOST=my-redis-host.example.org               # Redis host to store connections in
    $ uwsgi --http :8080 -w app --master -p 16 --locks 8

Features
========

* Read deltas from multiple VPC Flow Logs (multiple AWS accounts) in "parallel" (using gevent greenlets)
* Resolve DNS names for ELBs, public EC2 instances and RDS clusters
* Update Redis sorted sets with counter values
* Provide HTTP interface to retrieve inbound connections, endpoints and resolved addresses

How it works
============

* Connect to Team Service and fetch list of AWS accounts (``/api/accounts/aws``)
* Resolve NAT and "Odd" host (SSH jump host) IP addresses for all AWS accounts
* Start 16 background threads to process VPC Flow Logs for each account and region
* Find all public network interfaces per AWS account/region
* Collect DNS names for all public ELB load balancers
* Collect DNS names for all public RDS instances
* Collect names of all public EC2 instances
* Read VPC Flow Log records, for each record:

  * Check whether it belongs to a public interface
  * Check whether the source address is public
  * Lookup source IP address (either known IP or reverse DNS lookup)
  * Lookup destination address and replace with ELB, RDS or EC2 name
  * Increment counter in Redis for source, destination and destination port

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

    $ zign token -n test
    $ ./list-connections.py https://connection-tracker.example.org
    $ ./list-connections.py https://connection-tracker.example.org --suspicious
    $ ./scan-endpoints.py https://connection-tracker.example.org
    $ ./generate-account-graph.py https://connection-tracker.example.org --include mynetwork,myoffice

You can generate a CSV (tab separated) report for the last seven days:

.. code-block:: bash

    $ zign token -n test
    $ ./list-connections.py https://connection-tracker.example.org --suspicious --date-from "-7d" -o tsv > report.tsv


