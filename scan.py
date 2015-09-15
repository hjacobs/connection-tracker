#!/usr/bin/env python3

import collections
import datetime
import boto3
import ipaddress
import json
import netaddr
import logging
import os
import re
import requests
import socket
import tokens
import botocore.exceptions
from flowlogs_reader import FlowLogsReader
from redis import StrictRedis

AZ_NAMES_BY_REGION = {}
NAMES = {}
ACCOUNTS = {}
CONNECTIONS = {}

AWS_IPS = netaddr.IPSet()
AWS_S3_DOMAIN_PATTERN = re.compile('^s3.*amazonaws.com$')

redis = StrictRedis(host=os.getenv('REDIS_HOST') or 'localhost', port=int(os.getenv('REDIS_PORT') or '6379'))


def get_account_info(account: dict):
    account['domain'] = os.getenv('DOMAIN').format(account_name=account['name'])
    account['regions'] = os.getenv('REGIONS').split(',')
    return account


def update_accounts():
    r = requests.get(os.environ.get('HTTP_TEAM_SERVICE_URL') + '/api/accounts/aws',
                     headers={'Authorization': 'Bearer {}'.format(tokens.get('tok'))})
    for a in r.json():
        redis.set('accounts:' + a['id'], json.dumps(get_account_info(a)))
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


def get_key(account_id, region, day=None):
    if not day:
        now = datetime.datetime.utcnow()
        day = now.isoformat(' ').split()[0]
    key = 'connections:inbound:{}:{}:{}'.format(account_id, region, day)
    return key


def get_stored_connections(account_id, region, day=None):
    key = get_key(account_id, region, day)
    values = redis.zrange(key, 0, -1, withscores=True, desc=True)
    return [(k.decode('utf-8'), score) for k, score in values]


def update_connections(account_id, region):
    old_vals = get_stored_connections(account_id, region)
    try:
        conn = get_connections(account_id, region)
    except botocore.exceptions.ClientError as e:
        # just print a simple error, we expect some ResourceNotFound errors for accounts without VPC Flow Logs
        logging.error('%s: AWS client error: %s', account_id, e)
        return
    d = dict(old_vals)
    for c, val in conn.items():
        k = '{}->{}:{}'.format(c[0], c[1], c[2])
        old_val = d.get(k, 0)
        d[k] = old_val + val
    if d:
        key = get_key(account_id, region)
        redis.zadd(key, **d)


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
            if e.errno == 1:
                # do not attempt to resolv this IP again
                NAMES[ip] = None
            else:
                logging.exception('Could not resolve %s', ip)
    return NAMES.get(ip) or ip


def get_last_update(account_id, region):
    time_key = 'accounts:{}:{}:last_update'.format(account_id, region)
    last_update = redis.get(time_key)
    if last_update:
        return datetime.datetime.strptime(last_update.decode('utf-8'), '%Y-%m-%dT%H:%M:%S.%fZ')


def get_connections(account_id, region, connections=None):
    logging.info('%s: Connecting to {}..'.format(region), account_id)
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
            except:
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
                name = ''.join([x['Value'] for x in inst['Tags'] if x['Key'] == 'Name'])
                local_names[inst['PrivateIpAddress']] = '/'.join((name, inst.get('PublicIpAddress', '')))

    logging.info('%s: Got {} interfaces, {} load balancers and {} instances'.format(
                 len(interfaces), len(lb_dns_names), instance_count), account_id)

    connections = collections.Counter() if connections is None else connections
    now = datetime.datetime.utcnow()
    time_key = 'accounts:{}:{}:last_update'.format(account_id, region)
    start_time = get_last_update(account_id, region)
    if not start_time:
        start_time = now - datetime.timedelta(minutes=10)
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
                dest = interfaces.get(record.interface_id, {}).get('Description')
                if not dest or dest.startswith('Primary'):
                    # EC2 instance
                    if record.srcaddr in AWS_IPS and AWS_S3_DOMAIN_PATTERN.match(name.split('/')[0]):
                        # ignore S3 public IPs
                        # (most probably packets from S3 to public EC2)
                        continue
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
    redis.set(time_key, now.isoformat('T') + 'Z')
    return connections


def main():
    pass


if __name__ == '__main__':
    main()
