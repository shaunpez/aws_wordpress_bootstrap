aws_tools
---------

This repo contains tools for interacting with AWS that are Lucas Group-specific.

## bootstrap_wp_site.py

This tool creates an RDS cluster (with two instances, one primary and one read-replica), an EFS volume (with two mount points in two AZs), an ELB (with a leg in each AZ), and randomly-generated passwords.

This tool should be run after `salt-cloud` has created the EC2 instances but before `salt` has been run on them.

The configuration they use are in line with Lucas Group WP cluster standards.

To use, run: `python bootstrap_wp_site.py --sitecode <site code> --env <environment> --ssl <ssl cert name>`, replacing the variables with the correct information.

This tool does not create the EC2 instances, however--use `salt-cloud` for that.

Note that `--ssl` is an optional argument. If you don't specify this flag, an ELB will be created without an SSL listener.

This tool is only to be used for the initial bootstrapping. If you need to make changes afterwards, do so via the AWS console manually.

### TODO

* This tool does not generate a pillar config. It outputs the necessary information, but you'll have to manually copy the info over.
* Lots of hardcoded subnet IDs and security group IDs. Switching to a dynamic lookup would make this less fragile.
