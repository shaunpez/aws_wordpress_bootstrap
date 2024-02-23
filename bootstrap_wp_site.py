#!/usr/bin/env python
import argparse
import os
import random
import string
import subprocess
import time

import boto3
import pymysql.cursors

aws_profile_name = os.getenv('AWS_PROFILE', 'default')
aws_session = boto3.Session(profile_name=aws_profile_name)


def _generate_password():
    length = 25
    chars = string.ascii_letters + string.digits
    rnd = random.SystemRandom()
    password = ''.join(rnd.choice(chars) for i in range(length))
    return password


def _encrypt_secret(secret, secret_type='password'):
    if secret_type == 'password':
        pipe_command = 'echo'
    elif secret_type == 'key':
        pipe_command = 'cat'

    ps = subprocess.Popen((pipe_command, secret), stdout=subprocess.PIPE)
    encrypted_secret = subprocess.check_output(
        ['gpg', '--armor', '--encrypt', '-r webops@stickyagency.com'],
        stdin=ps.stdout
    )
    ps.wait()
    return encrypted_secret


def create_route53_records():
    # TODO
    route53 = aws_session.client('route53')
    return route53


def add_rds_user(rds_cluster, rds_master_password):
    wordpress_password = _generate_password()
    print 'Password for \'wordpress\' user:', wordpress_password
    print 'Encrypted:'
    print
    print _encrypt_secret(wordpress_password)

    db = pymysql.connect(host=rds_cluster,
                         user='master',
                         password=rds_master_password,
                         db='wordpress',
                         cursorclass=pymysql.cursors.DictCursor)

    try:
        print 'Creating \'wordpress\' user and adding grant'
        with db.cursor() as cursor:
            cursor.execute("""CREATE USER 'wordpress'@'%' IDENTIFIED BY '%s'""", (wordpress_password,))
            cursor.execute("""GRANT ALL PRIVILEGES ON wordpress.* TO 'wordpress'@'%'""")
            cursor.commit()
    finally:
        db.close()


def create_rds_cluster(environment, site_short_code):
    print 'Creating RDS cluster'
    rds = aws_session.client('rds')

    cluster_name = '-'.join((site_short_code, environment))

    rds_master_password = _generate_password()
    print 'RDS password for \'master\' user:', rds_master_password

    cluster_response = rds.create_db_cluster(
        AvailabilityZones=['us-east-2a', 'us-east-2b'],
        DatabaseName='wordpress',
        DBClusterIdentifier=cluster_name,
        DBSubnetGroupName='private-subnets',
        Engine='aurora',
        MasterUsername='master',
        MasterUserPassword=rds_master_password,
        Tags=[
            {'Key': 'Environment', 'Value': environment},
            {'Key': 'Business Unit', 'Value': site_short_code}
        ],
        StorageEncrypted=False,
    )

    if 'DBCluster' in cluster_response:
        cluster_endpoint = cluster_response.get('DBCluster').get('Endpoint')
        print 'Cluster %s created' % cluster_endpoint
    return (cluster_endpoint, rds_master_password)


def create_rds_instances(environment, site_short_code):
    print 'Creating RDS instances for cluster'
    rds = aws_session.client('rds')

    for db_instance in ['primary', 'replica']:
        db_instance_name = '-'.join((site_short_code, environment, db_instance))
        cluster_name = '-'.join((site_short_code, environment))

        rds.create_db_instance(
            DBInstanceIdentifier=db_instance_name,
            DBClusterIdentifier=cluster_name,
            DBInstanceClass='db.t2.medium',
            Engine='aurora',
            DBSubnetGroupName='private-subnets',
            PubliclyAccessible=False,
            Tags=[
                {'Key': 'Environment', 'Value': environment},
                {'Key': 'Business Unit', 'Value': site_short_code}
            ],
            CopyTagsToSnapshot=True
        )
        print 'Created DB instance:', db_instance_name


def create_efs_volume(environment, site_short_code):
    print 'Creating EFS volumes'
    efs = aws_session.client('efs')

    volume_name = '-'.join((site_short_code, 'wp', environment))

    file_system = efs.create_file_system(
        CreationToken=volume_name,
        PerformanceMode='generalPurpose'
    )

    print 'Created EFS volume:', volume_name

    print 'Sleeping for 60 seconds'
    time.sleep(60)

    efs.create_tags(
        FileSystemId=file_system.get('FileSystemId'),
        Tags=[
            {'Key': 'Name', 'Value': volume_name},
            {'Key': 'Business Unit', 'Value': site_short_code},
            {'Key': 'Environent', 'Value': environment}
        ]
    )

    for subnet in ['subnet-68dd1821', 'subnet-a063c0c7']:
        mount_target = efs.create_mount_target(
            FileSystemId=file_system.get('FileSystemId'),
            SubnetId=subnet,
            SecurityGroups=['sg-9f51d3e7', 'sg-95df54ed'],
        )
        print '    EFS Mount target:', mount_target.get('IpAddress')


def create_elb(environment, site_short_code, ssl_cert_name=None):
    if ssl_cert_name:
        print 'Creating ELB with SSL'
    else:
        print 'Creating ELB without SSL'

    elb = aws_session.client('elb')

    elb_name = '-'.join((site_short_code, environment))

    ssl_listener = [
        {
            'Protocol': 'HTTPS',
            'LoadBalancerPort': 443,
            'InstanceProtocol': 'HTTPS',
            'InstancePort': 443,
            'SSLCertificateId': 'arn:aws:iam::153734309294:server-certificate/%s' % ssl_cert_name
        }
    ]

    listener = [
        {
            'Protocol': 'HTTP',
            'LoadBalancerPort': 80,
            'InstanceProtocol': 'HTTP',
            'InstancePort': 80
        }
    ]

    if ssl_cert_name:
        listeners = listener + ssl_listener
    else:
        listeners = listener

    response = elb.create_load_balancer(
        LoadBalancerName=elb_name,
        Listeners=listeners,
        Subnets=['subnet-a163c0c6', 'subnet-6bdd1822'],
        SecurityGroups=['sg-3b3fb043'],
        Scheme='internet-facing',
        Tags=[
            {'Key': 'Name', 'Value': elb_name},
            {'Key': 'Environment', 'Value': environment},
            {'Key': 'Business Unit', 'Value': site_short_code}
        ]
    )

    # FIXME: The stickiness setup doesn't work
    elb.create_lb_cookie_stickiness_policy(
        LoadBalancerName=elb_name,
        PolicyName='three-hour-cookie',
        CookieExpirationPeriod=10800
    )

    elb.modify_load_balancer_attributes(
        LoadBalancerName=elb_name,
        LoadBalancerAttributes={
            'CrossZoneLoadBalancing': {
                'Enabled': True
            },
            'ConnectionDraining': {
                'Enabled': True,
                'Timeout': 300
            },
            'ConnectionSettings': {
                'IdleTimeout': 60
            },
            'AccessLog': {
                'Enabled': True,
                'S3BucketName': 'lucasgroup-access-logs',
                'EmitInterval': 60
            }
        }
    )

    print 'Created ELB %s: %s' % (elb_name, response.get('DNSName'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Bootstrap all required resources for a Wordpress cluster')
    parser.add_argument('--sitecode', help='The short code for the site (eg, hbny, sdww)', required=True)
    parser.add_argument('--env', help='The environment to create (stg or prod)', required=True)
    parser.add_argument('--ssl', help='The name of the IAM SSL cert to use (eg, star.lucas-group.com)', required=False)
    parser.add_argument('--sslkeyfile', help='The path to the SSL private key on disk', required=False)
    args = vars(parser.parse_args())

    site_short_code = args['sitecode']
    environment = args['env']

    if environment not in ['stg', 'prod']:
        print 'Invalid environment given. Please use one of: stg, prod'
        exit(1)

    if args['ssl']:
        ssl_cert_name = args['ssl']
    else:
        ssl_cert_name = None

    if args['sslkeyfile']:
        ssl_key_file = args['sslkeyfile']
    else:
        ssl_key_file = None

    print 'Generating resources for: %s-%s' % (site_short_code, environment)
    cluster_endpoint, rds_master_password = create_rds_cluster(environment, site_short_code)
    create_rds_instances(environment, site_short_code)
    create_efs_volume(environment, site_short_code)

    if ssl_cert_name:
        # create_elb(environment, site_short_code, ssl_cert_name=ssl_cert_name)
    else:
        # create_elb(environment, site_short_code)

    if ssl_key_file:
        print
        print 'Encrypted SSL private key:'
        print
        print _encrypt_secret(ssl_key_file, secret_type='key')
    print 'All done!'

    print 'Sleeping for ten minutes to allow the RDS cluster to come up'
    time.sleep(600)
    print 'Adding \'wordpress\' user to cluster'
    add_rds_user(cluster_endpoint, rds_master_password)
