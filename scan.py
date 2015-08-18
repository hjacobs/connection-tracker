#!/usr/bin/env python3

import collections
from clickclick import Action, info
import datetime
import boto3
import ipaddress
import socket
import sys
import yaml
from flowlogs_reader import FlowLogsReader

STUPS_CIDR = ipaddress.ip_network('172.31.0.0/16')

AZ_NAMES_BY_REGION = {}
NAMES = {}

def get_az_names(region: str):
    names = AZ_NAMES_BY_REGION.get(region)
    if not names:
        conn = boto3.client('ec2', region)
        ec2_zones = conn.describe_availability_zones(Filters=[{'Name': 'state', 'Values': ['available']}])
        names = [z['ZoneName'] for z in ec2_zones['AvailabilityZones']]
        AZ_NAMES_BY_REGION[region] = names
    return names


def get_trusted_addresses(config: dict):
    accounts = config.get('accounts', {})

    addresses = {}

    for name, cidr in config.get('global', {}).get('trusted_networks', {}).items():
        info('Adding trusted network {} ({})'.format(name, cidr))
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
                with Action('Checking {}'.format(domain)) as act:
                    try:
                        ai = socket.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
                    except:
                        ai = []
                        act.error('n/a')
                        pass
                    for _, _, _, _, ip_port in ai:
                        ip, _ = ip_port
                        addresses[ip] = domain

    return addresses


try:
    with open(sys.argv[2]) as fd:
        NAMES = yaml.load(fd)
except:
    with open(sys.argv[1]) as fd:
        config = yaml.load(fd)
    addresses = get_trusted_addresses(config)
    NAMES.update(addresses)

with open(sys.argv[2], 'w') as fd:
    yaml.dump(NAMES, fd)


ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')

elb = boto3.client('elb')


res = elb.describe_load_balancers()
for lb in res['LoadBalancerDescriptions']:
    if lb['Scheme'] == 'internet-facing':
        for sg_id in lb['SecurityGroups']:
            sg = ec2.SecurityGroup(sg_id)
            allow_all = False
            for rule in sg.ip_permissions:
                for ip_range in rule['IpRanges']:
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        allow_all = True
                        break
            if allow_all:
                info('LB {} allows traffic from everywhere'.format(lb['DNSName']))

instance_ids = []
interfaces = {}

with Action('Collecting network interfaces..'):
    res = ec2_client.describe_network_interfaces()
    for iface in res['NetworkInterfaces']:
        if 'Association' in iface:
            # public IP involved
            interfaces[iface['NetworkInterfaceId']] = iface
        if 'InstanceId' in iface['Attachment']:
            instance_ids.append(iface['Attachment']['InstanceId'])

with Action('Collecting public EC2 instances..'):
    res = ec2_client.describe_instances(InstanceIds=instance_ids)
    for reservation in res['Reservations']:
        for inst in reservation['Instances']:
            if 'PublicIpAddress' in inst and inst['PublicIpAddress'] not in NAMES:
                NAMES[inst['PublicIpAddress']] = ''.join([x['Value'] for x in inst['Tags'] if x['Key'] == 'Name'])
            if 'PrivateIpAddress' in inst:
                NAMES[inst['PrivateIpAddress']] = ''.join([x['Value'] for x in inst['Tags'] if x['Key'] == 'Name'])


connections = collections.Counter()
now = datetime.datetime.utcnow()
start_time = now - datetime.timedelta(minutes=60)
reader = FlowLogsReader('VPCFlowLogs', region_name='eu-west-1', start_time=start_time)
for record in reader:
    if record.action == 'ACCEPT':
        src = ipaddress.ip_address(record.srcaddr)
        if record.interface_id in interfaces and src not in STUPS_CIDR:
            dst = ipaddress.ip_address(record.dstaddr)
            name = NAMES.get(record.srcaddr, record.srcaddr)
            dest = interfaces.get(record.interface_id).get('Description') or NAMES.get(record.dstaddr, record.dstaddr)
            if 'NAT' not in dest and 'Odd' not in dest:
                conn = (name, dest, record.dstport)
                if conn not in connections:
                    print(' '.join(map(str, conn)))
                connections[conn] += 1

for conn, count in connections.most_common(50):
    print(' '.join(map(str, conn)), count)
