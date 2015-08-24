#!/usr/bin/env python3

import collections
import datetime
import boto3
import ipaddress
import netaddr
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
ACCOUNT_CONNECTIONS = collections.defaultdict(set)

LAST_TIMES = {}

AWS_IPS = netaddr.IPSet()


def get_account_info(account: dict):
    account['domain'] = os.getenv('DOMAIN').format(account_name=account['name'])
    account['regions'] = os.getenv('REGIONS').split(',')
    return account


def update_accounts():
    r = requests.get(os.environ.get('HTTP_TEAM_SERVICE_URL') + '/api/accounts/aws', headers={'Authorization': 'Bearer {}'.format(tokens.get('tok'))})
    ACCOUNTS.update({a['id']: get_account_info(a) for a in r.json()})


def update_addresses():
    res = get_addresses(ACCOUNTS)
    NAMES.update(res)


def get_az_names(region: str):
    names = AZ_NAMES_BY_REGION.get(region)
    if not names:
        conn = boto3.client('ec2', region)
        ec2_zones = conn.describe_availability_zones(Filters=[{'Name': 'state', 'Values': ['available']}])
        names = [z['ZoneName'] for z in ec2_zones['AvailabilityZones']]
        AZ_NAMES_BY_REGION[region] = names
    return names


def get_addresses(accounts: dict):
    addresses = {}

    for network in os.environ.get('NETWORKS', '').split(','):
        name, sep, cidr = network.partition('=')
        if name and cidr:
            logging.info('Adding network {} ({})'.format(name, cidr))
            for ip in ipaddress.ip_network(cidr):
                addresses[str(ip)] = name

    r = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
    data = r.json()
    for prefix in data['prefixes']:
        AWS_IPS.add(prefix['ip_prefix'])

    for account_id, cfg in accounts.items():
        for region in cfg['regions']:
            domains = set(['odd-{}.{}'.format(region, cfg.get('domain'))])
            for az in get_az_names(region):
                domains.add('nat-{}.{}'.format(az, cfg.get('domain')))
            for domain in sorted(domains):
                logging.info('Checking {}'.format(domain))
                try:
                    ai = socket.getaddrinfo(domain, 443, family=socket.AF_INET, socktype=socket.SOCK_STREAM)
                except:
                    ai = []
                    pass
                for _, _, _, _, ip_port in ai:
                    ip, _ = ip_port
                    addresses[ip] = '/'.join((account_id, region, domain))

    return addresses


def update_connections(account_id, region):
    conn = CONNECTIONS.get((account_id, region), collections.Counter())
    CONNECTIONS[(account_id, region)] = conn
    get_connections(account_id, region, conn)
    for c in conn:
        parts = c[0].split('/')
        if len(parts) >= 3:
            ACCOUNT_CONNECTIONS[(account_id, region)].add('/'.join(parts[:2]))


def get_lb_dns_names(session, lb_names):
    elb = session.client('elb')
    # TODO: might throw LoadBalancerNotFound
    res = elb.describe_load_balancers(LoadBalancerNames=lb_names)
    lb_dns_names = {}
    for lb in res['LoadBalancerDescriptions']:
        lb_dns_names[lb['LoadBalancerName']] = lb['DNSName']
    return lb_dns_names


def get_name(ip: str):
    if ip not in NAMES:
        try:
            info = socket.gethostbyaddr(ip)
            NAMES[ip] = '{}/{}'.format(info[0], ip)
        except socket.herror as e:
            # ignore "unknown host"
            if e.errno != 1:
                logging.exception('Could not resolve %s', ip)
    return NAMES.get(ip, ip)


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

    lb_dns_names = get_lb_dns_names(session, lb_names)

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
                NAMES[ip] = '/'.join((account_id, region, host))

    local_names = {}
    instance_count = 0
    logging.info('%s: Collecting public EC2 instances..', account_id)
    res = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in res['Reservations']:
        for inst in reservation['Instances']:
            instance_count += 1
            if 'PrivateIpAddress' in inst and 'Tags' in inst:
                local_names[inst['PrivateIpAddress']] = ''.join([x['Value'] for x in inst['Tags'] if x['Key'] == 'Name']) + '/' + inst.get('PublicIpAddress', '')

    logging.info('%s: Got {} interfaces, {} load balancers and {} instances'.format(len(interfaces), len(lb_dns_names), instance_count), account_id)

    connections = collections.Counter() if connections is None else connections
    now = datetime.datetime.utcnow()
    start_time = LAST_TIMES.get(account_id, now - datetime.timedelta(minutes=10))
    reader = FlowLogsReader('vpc-flowgroup', region_name=region, start_time=start_time, end_time=now)
    reader.logs_client = session.client('logs')
    record_count = 0
    new_connections = 0
    for record in reader:
        # just consider accepted packets
        if record.action == 'ACCEPT':
            record_count += 1
            src = ipaddress.ip_address(record.srcaddr)
            # only look at packets received at public interfaces
            if record.interface_id in interfaces and not src.is_private:
                name = get_name(record.srcaddr)
                if record.srcaddr in AWS_IPS:
                    print(name, record.srcaddr)
                dest = interfaces.get(record.interface_id, {}).get('Description')
                if not dest or dest.startswith('Primary'):
                    # EC2 instance
                    dest = local_names.get(record.dstaddr, record.dstaddr)
                elif dest.startswith('ELB'):
                    # ELB
                    words = dest.split()
                    dest = lb_dns_names.get(words[-1], dest)
                elif dest.startswith('RDS'):
                    # RDS instance
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
