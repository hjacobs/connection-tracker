#!/usr/bin/env python3

import collections
import datetime
import boto3
import ipaddress
import logging
import os
import requests
import socket
import tokens
from flowlogs_reader import FlowLogsReader

AZ_NAMES_BY_REGION = {}
NAMES = {}
ACCOUNTS = {}
CONNECTIONS = {}

LAST_TIMES = {}


def update_accounts():
    r = requests.get(os.environ.get('HTTP_TEAM_SERVICE_URL') + '/api/accounts/aws', headers={'Authorization': 'Bearer {}'.format(tokens.get('tok'))})
    ACCOUNTS.update({a['id']: a for a in r.json()})


def update_addresses():
    config = {'regions': ['eu-west-1'],
              'accounts': {a['name']: {'domain': os.getenv('DOMAIN'), 'regions': ['eu-west-1']} for a in ACCOUNTS.values()}}
    res = get_addresses(config)
    NAMES.update(res)


def get_az_names(region: str):
    names = AZ_NAMES_BY_REGION.get(region)
    if not names:
        conn = boto3.client('ec2', region)
        ec2_zones = conn.describe_availability_zones(Filters=[{'Name': 'state', 'Values': ['available']}])
        names = [z['ZoneName'] for z in ec2_zones['AvailabilityZones']]
        AZ_NAMES_BY_REGION[region] = names
    return names


def get_addresses(config: dict):
    accounts = config.get('accounts', {})

    addresses = {}

    for network in os.environ.get('NETWORKS', '').split(','):
        name, sep, cidr = network.partition('=')
        if name and cidr:
            logging.info('Adding network {} ({})'.format(name, cidr))
            for ip in ipaddress.ip_network(cidr):
                addresses[str(ip)] = name

    for account_name, _cfg in accounts.items():
        cfg = {}
        cfg.update(config.get('global', {}))
        if _cfg:
            cfg.update(_cfg)
        for region in cfg['regions']:
            domains = set(['odd-{}.{}'.format(region, cfg.get('domain').format(account_name=account_name))])
            for az in get_az_names(region):
                domains.add('nat-{}.{}'.format(az, cfg.get('domain').format(account_name=account_name)))
            for domain in sorted(domains):
                logging.info('Checking {}'.format(domain))
                try:
                    ai = socket.getaddrinfo(domain, 443, family=socket.AF_INET, socktype=socket.SOCK_STREAM)
                except:
                    ai = []
                    pass
                for _, _, _, _, ip_port in ai:
                    ip, _ = ip_port
                    addresses[ip] = domain

    return addresses


def update_connections(account_id, region):
    conn = CONNECTIONS.get((account_id, region), collections.Counter())
    CONNECTIONS[(account_id, region)] = conn
    get_connections(account_id, region, conn)


def get_connections(account_id, region, connections=None):
    logging.info('Getting connections for {} {}..'.format(account_id, region))
    sts = boto3.client('sts')
    response = sts.assume_role(RoleArn='arn:aws:iam::' + account_id + ':role/fullstop',
                               RoleSessionName='fullstop',
                               DurationSeconds=900)

    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                            aws_session_token=response['Credentials']['SessionToken'],
                            region_name=region)

    ec2_client = session.client('ec2')
    elb = session.client('elb')
    rds = session.client('rds')

    instance_ids = []
    interfaces = {}

    logging.info('%s: Collecting network interfaces..', account_id)
    res = ec2_client.describe_network_interfaces()
    lb_names = []
    for iface in res['NetworkInterfaces']:
        if 'Association' in iface:
            # public IP involved
            interfaces[iface['NetworkInterfaceId']] = iface
            descr = iface.get('Description')
            if descr.startswith('ELB'):
                words = descr.split()
                lb_names.append(words[-1])
        if 'Attachment' in iface and 'InstanceId' in iface['Attachment']:
            instance_ids.append(iface['Attachment']['InstanceId'])

    res = elb.describe_load_balancers(LoadBalancerNames=lb_names)
    lb_dns_names = {}
    for lb in res['LoadBalancerDescriptions']:
        lb_dns_names[lb['LoadBalancerName']] = lb['DNSName']

    res = rds.describe_db_instances()
    for db in res['DBInstances']:
        if db['PubliclyAccessible']:
            host, port = (db['Endpoint']['Address'], db['Endpoint']['Port'])
            try:
                ai = socket.getaddrinfo(host, port, family=socket.AF_INET, socktype=socket.SOCK_STREAM)
            except Exception as e:
                print(e)
                ai = []
            for _, _, _, _, ip_port in ai:
                ip, _ = ip_port
                NAMES[ip] = host

    local_names = {}
    instance_count = 0
    logging.info('%s: Collecting public EC2 instances..', account_id)
    res = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in res['Reservations']:
        for inst in reservation['Instances']:
            instance_count += 1
            if 'PrivateIpAddress' in inst and 'Tags' in inst:
                local_names[inst['PrivateIpAddress']] = ''.join([x['Value'] for x in inst['Tags'] if x['Key'] == 'Name']) + '/' + inst.get('PublicIpAddress', '')

    logging.info('%s: Got {} interfaces and {} instances'.format(len(interfaces), instance_count), account_id)

    connections = collections.Counter() if connections is None else connections
    now = datetime.datetime.utcnow()
    start_time = LAST_TIMES.get(account_id, now - datetime.timedelta(minutes=10))
    reader = FlowLogsReader('vpc-flowgroup', region_name=region, start_time=start_time, end_time=now)
    reader.logs_client = session.client('logs')
    record_count = 0
    new_connections = 0
    for record in reader:
        if record.action == 'ACCEPT':
            record_count += 1
            src = ipaddress.ip_address(record.srcaddr)
            if record.interface_id in interfaces and not src.is_private:
                name = NAMES.get(record.srcaddr, record.srcaddr)
                dest = interfaces.get(record.interface_id, {}).get('Description')
                if not dest or dest.startswith('Primary'):
                    dest = NAMES.get(record.dstaddr, local_names.get(record.dstaddr, record.dstaddr))
                elif dest.startswith('ELB'):
                    words = dest.split()
                    dest = lb_dns_names.get(words[-1], dest)
                elif dest.startswith('RDS'):
                    public_ip = interfaces.get(record.interface_id, {}).get('Association', {}).get('PublicIp', '')
                    dest = NAMES.get(public_ip, 'RDS/' + public_ip)
                elif dest:
                    dest += '/' + interfaces.get(record.interface_id, {}).get('Association', {}).get('PublicIp', '')
                if 'NAT' not in dest and 'Odd' not in dest:
                    conn = (name, dest, record.dstport)
                    if conn not in connections:
                        new_connections += 1
                    connections[conn] += 1
    logging.info('%s: Got {} records and {} new connections'.format(record_count, new_connections), account_id)
    LAST_TIMES[account_id] = now
    return connections


def main():
    pass


if __name__ == '__main__':
    main()
