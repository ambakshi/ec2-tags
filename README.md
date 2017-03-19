# ec2-tags
Run without arguments, `ec2-tags` prints out the local instance's tags. In this
example, the instance is tagged with cluster, role and name.

    root@ip-172-31-25-216:~# ec2-tags
    ec2_tag_cluster=jenkins-slave
    ec2_tag_role=builder
    ec2_tag_name=jenkins-slave-aws-ub14-0

## Extra instance information
Passing `-i` will add information about the ec2 instance.

    root@ip-172-31-25-216:~# ec2-tags -i
    ec2_tag_name=jenkins-slave-aws-ub14-0
    ec2_tag_cluster=jenkins-slave
    ec2_tag_role=builder
    ec2_instance_id=i-0aaaaabbbcccc
    ec2_instance_type=m3.2xlarge
    ec2_local_ipv4=172.31.25.216
    ec2_public_ipv4=12.42.85.95
    ec2_region=us-west-2

## Use with bash
Get the same info suitable for use from bash (via eval or source)

    root@ip-172-31-25-216:~# ec2-tags -i -s -e
    export NAME='jenkins-slave-aws-ub14-0'
    export CLUSTER='jenkins-slave'
    export ROLE='builder'
    export INSTANCE_ID='i-0aaaaabbbcccc'
    export INSTANCE_TYPE='m3.2xlarge'
    export EC2_LOCAL_IPV4='172.31.25.216'
    export EC2_PUBLIC_IPV4='12.42.85.95'
    export AWS_DEFAULT_REGION='us-west-2'

## Use with facter/puppet
Place the executable inside /etc/facter/facts.d directory and get the same values as puppet facts!

    root@ip-172-31-25-216:~# mkdir -p /etc/facter/facts.d
    root@ip-172-31-25-216:~# cp ec2-tags /etc/facter/facts.d
    root@ip-172-31-25-216:~# facter -p | grep ec2_tag_
    ec2_tag_cluster => jenkins-slave
    ec2_tag_name => jenkins-slave-aws-ub14-0
    ec2_tag_role => builder

