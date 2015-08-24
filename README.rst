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
    $ ./app.py
