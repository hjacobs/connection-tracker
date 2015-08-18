#!/usr/bin/env python3

import boto3
import ipaddress
from flowlogs_reader import FlowLogsReader

STUPS_CIDR = ipaddress.ip_network('172.31.0.0/16')

ec2 = boto3.resource('ec2')
elb = boto3.client('elb')


reader = FlowLogsReader('VPCFlowLogs', region_name='eu-west-1')
for record in reader:
    src = ipaddress.ip_address(record.srcaddr)
    dst = ipaddress.ip_address(record.dstaddr)
    if src not in STUPS_CIDR or dst not in STUPS_CIDR:
        print(src, record.srcport, dst, record.dstport)



res = elb.describe_load_balancers()
for lb in res['LoadBalancerDescriptions']:
    if lb['Scheme'] == 'internet-facing':
        print(lb['DNSName'])
        for sg_id in lb['SecurityGroups']:
            sg = ec2.SecurityGroup(sg_id)
            print(sg.ip_permissions)

ec2_client = boto3.client('ec2')
res = ec2_client.describe_addresses()
if_ids = []
for addr in res['Addresses']:
    if_ids.append(addr['NetworkInterfaceId'])
    print(addr)

instance_ids = []

res = ec2_client.describe_network_interfaces(NetworkInterfaceIds=if_ids)
for iface in res['NetworkInterfaces']:
    instance_ids.append(iface['Attachment']['InstanceId'])
    print(iface)

res = ec2_client.describe_instances(InstanceIds=instance_ids)
for reservation in res['Reservations']:
    for inst in reservation['Instances']:
        print(inst['Tags'])

