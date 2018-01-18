import string
import random
import uuid
import hashlib

class CfnReturns(object):
    '''Generates valid-looking AWS references and attributes'''

    def __init__(self):
        pass

    def gen_alnumchars(self, num_chars, upper = False):
        ret = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(num_chars))
        if not upper:
            ret = ret.lower()
        
        return ret

    def gen_hexchars(self, num_chars, upper = False):
        ret = ''.join(random.choice('0123456789ABCDEF') for _ in range(num_chars))
        if not upper:
            ret = ret.lower()

        return ret

    def gen_uuid(self):
        return str(uuid.uuid4())

    def gen_publicip(self):
        rndsubnet = random.choice(['192.0.2', '198.51.100', '203.0.113']) # RFC 5737
        rndoct = str(random.randint(2, 254))
        return '%s.%s' % (rndsubnet, rndoct)

    def get_ref(self, res, res_name='myresource', stack_name='mystack', region='us-east-1', accountid='123456789012'):
        return self.get_returns(res, res_name, stack_name, region)['Ref']['value']

    def get_returns(self, res, res_name='myresource', stack_name='mystack', region='us-east-1', accountid='123456789012'):
        random.seed(int(hashlib.md5(res_name + stack_name + region + accountid).hexdigest(), 16))
        
        res_type = res['Type']

        if res_type == 'AWS::ApiGateway::Account':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::ApiKey':
            return {
                'Ref': {
                    'value': self.gen_alnumchars(10),
                    'randomness': True
                }
            }
        elif res_type == 'AWS::ApiGateway::Authorizer':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::BasePathMapping':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::ClientCertificate':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::Deployment':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::DocumentationPart':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::DocumentationVersion':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::DomainName':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::GatewayResponse':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::Method':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::Model':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::RequestValidator':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::Resource':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::RestApi':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::Stage':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::UsagePlan':
            raise NotImplementedError
        elif res_type == 'AWS::ApiGateway::UsagePlanKey':
            raise NotImplementedError
        elif res_type == 'AWS::ApplicationAutoScaling::ScalableTarget':
            raise NotImplementedError
        elif res_type == 'AWS::ApplicationAutoScaling::ScalingPolicy':
            raise NotImplementedError
        elif res_type == 'AWS::Athena::NamedQuery':
            raise NotImplementedError
        elif res_type == 'AWS::AutoScaling::AutoScalingGroup':
            raise NotImplementedError
        elif res_type == 'AWS::AutoScaling::LaunchConfiguration':
            raise NotImplementedError
        elif res_type == 'AWS::AutoScaling::LifecycleHook':
            raise NotImplementedError
        elif res_type == 'AWS::AutoScaling::ScalingPolicy':
            raise NotImplementedError
        elif res_type == 'AWS::AutoScaling::ScheduledAction':
            raise NotImplementedError
        elif res_type == 'AWS::Batch::ComputeEnvironment':
            raise NotImplementedError
        elif res_type == 'AWS::Batch::JobDefinition':
            raise NotImplementedError
        elif res_type == 'AWS::Batch::JobQueue':
            raise NotImplementedError
        elif res_type == 'AWS::CertificateManager::Certificate':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFormation::Authentication':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFormation::CustomResource':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFormation::Init':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFormation::Interface':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFormation::Stack':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFormation::WaitCondition':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFormation::WaitConditionHandle':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFront::Distribution':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFront::CloudFrontOriginAccessIdentity':
            raise NotImplementedError
        elif res_type == 'AWS::CloudFront::StreamingDistribution':
            raise NotImplementedError
        elif res_type == 'AWS::CloudTrail::Trail':
            raise NotImplementedError
        elif res_type == 'AWS::CloudWatch::Alarm':
            raise NotImplementedError
        elif res_type == 'AWS::CloudWatch::Dashboard':
            raise NotImplementedError
        elif res_type == 'AWS::CodeBuild::Project':
            raise NotImplementedError
        elif res_type == 'AWS::CodeCommit::Repository':
            return {
                'Ref': {
                    'value': self.gen_uuid(),
                    'randomness': True
                },
                'Fn::GetAtt': {
                    'Arn': {
                        'value': 'arn:aws:codecommit:%s:%s:%s' % (region, accountid, res['Properties']['RepositoryName']), # TODO Check for RepositoryName trimming here
                        'randomness': False
                    },
                    'CloneUrlHttp': {
                        'value': 'https://codecommit.%s.amazonaws.com/v1/repos/%s' % (region, res['Properties']['RepositoryName']),
                        'randomness': False
                    },
                    'CloneUrlSsh': {
                        'value': 'ssh://git-codecommit.%s.amazonaws.com/v1/repos//v1/repos/%s' % (region, res['Properties']['RepositoryName']),
                        'randomness': False
                    },
                    'Name': {
                        'value': res['Properties']['RepositoryName'],
                        'randomness': False
                    }
                }
            }
        elif res_type == 'AWS::CodeDeploy::Application':
            raise NotImplementedError
        elif res_type == 'AWS::CodeDeploy::DeploymentConfig':
            raise NotImplementedError
        elif res_type == 'AWS::CodeDeploy::DeploymentGroup':
            raise NotImplementedError
        elif res_type == 'AWS::CodePipeline::CustomActionType':
            raise NotImplementedError
        elif res_type == 'AWS::CodePipeline::Pipeline':
            raise NotImplementedError
        elif res_type == 'AWS::Cognito::IdentityPool':
            raise NotImplementedError
        elif res_type == 'AWS::Cognito::IdentityPoolRoleAttachment':
            raise NotImplementedError
        elif res_type == 'AWS::Cognito::UserPool':
            raise NotImplementedError
        elif res_type == 'AWS::Cognito::UserPoolClient':
            raise NotImplementedError
        elif res_type == 'AWS::Cognito::UserPoolGroup':
            raise NotImplementedError
        elif res_type == 'AWS::Cognito::UserPoolUser':
            raise NotImplementedError
        elif res_type == 'AWS::Cognito::UserPoolUserToGroupAttachment':
            raise NotImplementedError
        elif res_type == 'AWS::Config::ConfigRule':
            raise NotImplementedError
        elif res_type == 'AWS::Config::ConfigurationRecorder':
            raise NotImplementedError
        elif res_type == 'AWS::Config::DeliveryChannel':
            raise NotImplementedError
        elif res_type == 'AWS::DataPipeline::Pipeline':
            raise NotImplementedError
        elif res_type == 'AWS::DAX::Cluster':
            raise NotImplementedError
        elif res_type == 'AWS::DAX::ParameterGroup':
            raise NotImplementedError
        elif res_type == 'AWS::DAX::SubnetGroup':
            raise NotImplementedError
        elif res_type == 'AWS::DirectoryService::MicrosoftAD':
            raise NotImplementedError
        elif res_type == 'AWS::DirectoryService::SimpleAD':
            raise NotImplementedError
        elif res_type == 'AWS::DMS::Certificate':
            raise NotImplementedError
        elif res_type == 'AWS::DMS::Endpoint':
            raise NotImplementedError
        elif res_type == 'AWS::DMS::EventSubscription':
            raise NotImplementedError
        elif res_type == 'AWS::DMS::ReplicationInstance':
            raise NotImplementedError
        elif res_type == 'AWS::DMS::ReplicationSubnetGroup':
            raise NotImplementedError
        elif res_type == 'AWS::DMS::ReplicationTask':
            raise NotImplementedError
        elif res_type == 'AWS::DynamoDB::Table':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::CustomerGateway':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::DHCPOptions':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::EgressOnlyInternetGateway':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::EIP':
            return {
                'Ref': {
                    'value': self.gen_publicip(),
                    'randomness': True
                }
            }
        elif res_type == 'AWS::EC2::EIPAssociation':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::FlowLog':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::Host':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::Instance':
            rndoct = str(randint(4, 254))

            return {
                'Ref': {
                    'value': 'i-0%s' % (self.gen_hexchars(16)),
                    'randomness': True
                },
                'Fn::GetAtt': {
                    'AvailabilityZone': {
                        'value': '%sa' % (region),
                        'randomness': True # TODO: Check me
                    },
                    'PrivateDnsName': {
                        'value': 'ip-10-0-0-%s.ec2.internal' % (rndoct),
                        'randomness': True,
                        'requiresMoreInfo': True
                    },
                    'PublicDnsName': {
                        'value': 'ec2-100-0-0-%s.compute-1.amazonaws.com' % (rndoct),
                        'randomness': True,
                        'requiresMoreInfo': True
                    },
                    'PrivateIp': {
                        'value': '10.0.0.%s' % (rndoct),
                        'randomness': True,
                        'requiresMoreInfo': True
                    },
                    'PublicIp': {
                        'value': '100.0.0.%s' % (rndoct),
                        'randomness': True,
                        'requiresMoreInfo': True
                    }
                }
            }
        elif res_type == 'AWS::EC2::InternetGateway':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::NatGateway':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::NetworkAcl':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::NetworkAclEntry':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::NetworkInterface':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::NetworkInterfaceAttachment':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::NetworkInterfacePermission':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::PlacementGroup':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::Route':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::RouteTable':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::SecurityGroup':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::SecurityGroupEgress':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::SecurityGroupIngress':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::SpotFleet':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::Subnet':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::SubnetCidrBlock':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::SubnetNetworkAclAssociation':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::SubnetRouteTableAssociation':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::Volume':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VolumeAttachment':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPC':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPCCidrBlock':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPCDHCPOptionsAssociation':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPCEndpoint':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPCGatewayAttachment':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPCPeeringConnection':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPNConnection':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPNConnectionRoute':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPNGateway':
            raise NotImplementedError
        elif res_type == 'AWS::EC2::VPNGatewayRoutePropagation':
            raise NotImplementedError
        elif res_type == 'AWS::ECR::Repository':
            raise NotImplementedError
        elif res_type == 'AWS::ECS::Cluster':
            raise NotImplementedError
        elif res_type == 'AWS::ECS::Service':
            raise NotImplementedError
        elif res_type == 'AWS::ECS::TaskDefinition':
            raise NotImplementedError
        elif res_type == 'AWS::EFS::FileSystem':
            raise NotImplementedError
        elif res_type == 'AWS::EFS::MountTarget':
            raise NotImplementedError
        elif res_type == 'AWS::ElastiCache::CacheCluster':
            raise NotImplementedError
        elif res_type == 'AWS::ElastiCache::ParameterGroup':
            raise NotImplementedError
        elif res_type == 'AWS::ElastiCache::ReplicationGroup':
            raise NotImplementedError
        elif res_type == 'AWS::ElastiCache::SecurityGroup':
            raise NotImplementedError
        elif res_type == 'AWS::ElastiCache::SecurityGroupIngress':
            raise NotImplementedError
        elif res_type == 'AWS::ElastiCache::SubnetGroup':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticBeanstalk::Application':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticBeanstalk::ApplicationVersion':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticBeanstalk::ConfigurationTemplate':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticBeanstalk::Environment':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticLoadBalancing::LoadBalancer':
            ref = '%s-%s-%s' % (stack_name[:9], res_name[:8], self.gen_alnumchars(12, True))
            rnddnsext = str(random.randint(100000000, 999999999))
            internalprefix = ''
            dnsname = '%s%s-%s.%s.elb.amazonaws.com' % (internalprefix, ref, rnddnsext, region)
            zonename = dnsname
            sg_groupname = "%s-InstanceSecurityGroup-%s" % (stack_name, self.gen_alnumchars(13, True)) # Will stack_name be truncated?
            if res:
                if 'Properties' in res and 'Scheme' in res['Properties'] and res['Properties']['Scheme'] == 'internal':
                    internalprefix = 'internal-'
            else:
                confident = False
            
            return {
                'Ref': {
                    'value': ref,
                    'randomness': True
                },
                'Fn::GetAtt': {
                    'CanonicalHostedZoneName': {
                        'value': zonename, #TODO For internal, might look like: int-ElasticLoadBal-1PNEJ1505X77D
                        'randomness': True
                    },
                    'CanonicalHostedZoneNameID': {
                        'value': 'Z%s' % (self.gen_alnumchars(13, True)),
                        'randomness': True
                    },
                    'DNSName': {
                        'value': dnsname,
                        'randomness': True
                    }
                    'SourceSecurityGroup.GroupName': {
                        'value': sg_groupname, #TODO Finish this off  NO SG / Subs set: default_elb_ff5c503c-0ae1-36c9-abc7-005bf976ac13   maybe different for internal
                        'randomness': True,
                        'requiresMoreInfo': True
                    }
                    'SourceSecurityGroup.OwnerAlias': {
                        'value': accountid,
                        'randomness': False
                    }
                }
            }
        elif res_type == 'AWS::ElasticLoadBalancingV2::Listener':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticLoadBalancingV2::ListenerCertificate':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticLoadBalancingV2::ListenerRule':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticLoadBalancingV2::LoadBalancer':
            raise NotImplementedError
        elif res_type == 'AWS::ElasticLoadBalancingV2::TargetGroup':
            raise NotImplementedError
        elif res_type == 'AWS::Elasticsearch::Domain':
            raise NotImplementedError
        elif res_type == 'AWS::EMR::Cluster':
            raise NotImplementedError
        elif res_type == 'AWS::EMR::InstanceFleetConfig':
            raise NotImplementedError
        elif res_type == 'AWS::EMR::InstanceGroupConfig':
            raise NotImplementedError
        elif res_type == 'AWS::EMR::SecurityConfiguration':
            raise NotImplementedError
        elif res_type == 'AWS::EMR::Step':
            raise NotImplementedError
        elif res_type == 'AWS::Events::Rule': # TODO: Needs testing
            name = self.gen_alnumchars(12, True)
            randomness = True
            if 'Name' in res['Properties']:
                name = res['Properties']['Name']
                randomness = False
            
            return {
                'Ref': {
                    'value': name,
                    'randomness': randomness
                },
                'Fn::GetAtt': {
                    'Arn': {
                        'name': 'arn:aws:events:%s:%s:rule/%s' % (region, accountid, name),
                        'randomness': randomness
                    }
                }
            }
        elif res_type == 'AWS::GameLift::Alias':
            raise NotImplementedError
        elif res_type == 'AWS::GameLift::Build':
            raise NotImplementedError
        elif res_type == 'AWS::GameLift::Fleet':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::Classifier':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::Connection':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::Crawler':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::Database':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::DevEndpoint':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::Job':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::Partition':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::Table':
            raise NotImplementedError
        elif res_type == 'AWS::Glue::Trigger':
            raise NotImplementedError
        elif res_type == 'AWS::IAM::AccessKey':
            raise NotImplementedError
        elif res_type == 'AWS::IAM::Group':
            raise NotImplementedError
        elif res_type == 'AWS::IAM::InstanceProfile':
            raise NotImplementedError
        elif res_type == 'AWS::IAM::ManagedPolicy':
            raise NotImplementedError
        elif res_type == 'AWS::IAM::Policy':
            raise NotImplementedError
        elif res_type == 'AWS::IAM::Role':
            raise NotImplementedError
        elif res_type == 'AWS::IAM::User':
            raise NotImplementedError
        elif res_type == 'AWS::IAM::UserToGroupAddition':
            raise NotImplementedError
        elif res_type == 'AWS::IoT::Certificate':
            raise NotImplementedError
        elif res_type == 'AWS::IoT::Policy':
            raise NotImplementedError
        elif res_type == 'AWS::IoT::PolicyPrincipalAttachment':
            raise NotImplementedError
        elif res_type == 'AWS::IoT::Thing':
            raise NotImplementedError
        elif res_type == 'AWS::IoT::ThingPrincipalAttachment':
            raise NotImplementedError
        elif res_type == 'AWS::IoT::TopicRule':
            raise NotImplementedError
        elif res_type == 'AWS::Kinesis::Stream':
            raise NotImplementedError
        elif res_type == 'AWS::KinesisAnalytics::Application':
            raise NotImplementedError
        elif res_type == 'AWS::KinesisAnalytics::ApplicationOutput':
            raise NotImplementedError
        elif res_type == 'AWS::KinesisAnalytics::ApplicationReferenceDataSource':
            raise NotImplementedError
        elif res_type == 'AWS::KinesisFirehose::DeliveryStream':
            raise NotImplementedError
        elif res_type == 'AWS::KMS::Alias':
            raise NotImplementedError
        elif res_type == 'AWS::KMS::Key':
            raise NotImplementedError
        elif res_type == 'AWS::Lambda::EventSourceMapping':
            raise NotImplementedError
        elif res_type == 'AWS::Lambda::Alias':
            raise NotImplementedError
        elif res_type == 'AWS::Lambda::Function':
            lambdaname = "MyLambdaFunction"
            if res:
                if 'Properties' in res and 'FunctionName' in res['Properties']:
                    lambdaname = res['FunctionName']
            else:
                confident = False
            lambdaref = '%s-%s-%s' % (stack_name, lambdaname, self.gen_alnumchars(12, True))

            return {
                'Ref': {
                    'value': lambdaref,
                    'randomness': True
                },
                'Fn::GetAtt': {
                    'Arn': {
                        'value': 'arn:aws:lambda:%s:%s:%s' % (region, accountid, lambdaref),
                        'randomness': True
                    }
                }
            }
        elif res_type == 'AWS::Lambda::Permission':
            return {
                'Ref': {
                    'value': '%s-%s-%s' % (stack_name, res_name, self.gen_alnumchars(13, True)),
                    'randomness': True
                }
            }
        elif res_type == 'AWS::Lambda::Version':
            raise NotImplementedError
        elif res_type == 'AWS::Logs::Destination':
            raise NotImplementedError
        elif res_type == 'AWS::Logs::LogGroup':
            raise NotImplementedError
        elif res_type == 'AWS::Logs::LogStream':
            raise NotImplementedError
        elif res_type == 'AWS::Logs::MetricFilter':
            raise NotImplementedError
        elif res_type == 'AWS::Logs::SubscriptionFilter':
            raise NotImplementedError
        elif res_type == 'AWS::OpsWorks::App':
            raise NotImplementedError
        elif res_type == 'AWS::OpsWorks::ElasticLoadBalancerAttachment':
            raise NotImplementedError
        elif res_type == 'AWS::OpsWorks::Instance':
            raise NotImplementedError
        elif res_type == 'AWS::OpsWorks::Layer':
            raise NotImplementedError
        elif res_type == 'AWS::OpsWorks::Stack':
            raise NotImplementedError
        elif res_type == 'AWS::OpsWorks::UserProfile':
            raise NotImplementedError
        elif res_type == 'AWS::OpsWorks::Volume':
            raise NotImplementedError
        elif res_type == 'AWS::RDS::DBCluster':
            clusterid = self.gen_alnumchars(12, False)
            rdsclusterref = '%s-%s-%s' % (res_name, rdsinstanceid, clusterid)
            rdsclusterroref = '%s-%s-ro-%s' % (res_name, rdsinstanceid, clusterid)
            alt_clusterid = self.gen_alnumchars(12, False)

            return {
                'Ref': {
                    'value': rdsclusterref,
                    'randomness': True
                },
                'Fn::GetAtt': {
                    'Endpoint.Address': {
                        'value': '%s.%s.%s.rds.amazonaws.com' % (rdsclusterref, alt_clusterid, region),
                        'randomness': True
                    },
                    'Endpoint.Port': {
                        'value': '5439', # TODO: Fix me, I am dependant upon the property and engine
                        'randomness': False
                    },
                    'ReadEndpoint.Address': {
                        'value': '%s.%s.%s.rds.amazonaws.com' % (rdsclusterroref, alt_clusterid, region),
                        'randomness': True
                    }
                }
            }
        elif res_type == 'AWS::RDS::DBClusterParameterGroup':
            raise NotImplementedError
        elif res_type == 'AWS::RDS::DBInstance':
            rdsinstanceid = "MyRDSInstance"
            if res:
                if 'Properties' in res and 'DBInstanceIdentifier' in res['Properties']:
                    rdsinstanceid = res['DBInstanceIdentifier']
            else:
                confident = False
            rdsinstanceref = '%s-%s-%s' % (stack_name, rdsinstanceid, self.gen_alnumchars(12, False))

            return {
                'Ref': {
                    'value': rdsinstanceref,
                    'randomness': True
                },
                'Fn::GetAtt': {
                    'Endpoint.Address': {
                        'value': '%s.%s.%s.rds.amazonaws.com' % (rdsinstanceref, self.gen_alnumchars(12, False), region),
                        'randomness': True
                    },
                    'Endpoint.Port': {
                        'value': '3306', # TODO: Fix me, I am dependant upon the property and engine
                        'randomness': False
                    }
                }
            }
        elif res_type == 'AWS::RDS::DBParameterGroup':
            raise NotImplementedError
        elif res_type == 'AWS::RDS::DBSecurityGroup':
            raise NotImplementedError
        elif res_type == 'AWS::RDS::DBSecurityGroupIngress':
            raise NotImplementedError
        elif res_type == 'AWS::RDS::DBSubnetGroup':
            raise NotImplementedError
        elif res_type == 'AWS::RDS::EventSubscription':
            raise NotImplementedError
        elif res_type == 'AWS::RDS::OptionGroup':
            raise NotImplementedError
        elif res_type == 'AWS::Redshift::Cluster':
            raise NotImplementedError
        elif res_type == 'AWS::Redshift::ClusterParameterGroup':
            raise NotImplementedError
        elif res_type == 'AWS::Redshift::ClusterSecurityGroup':
            raise NotImplementedError
        elif res_type == 'AWS::Redshift::ClusterSecurityGroupIngress':
            raise NotImplementedError
        elif res_type == 'AWS::Redshift::ClusterSubnetGroup':
            raise NotImplementedError
        elif res_type == 'AWS::Route53::HealthCheck':
            raise NotImplementedError
        elif res_type == 'AWS::Route53::HostedZone':
            raise NotImplementedError
        elif res_type == 'AWS::Route53::RecordSet':
            raise NotImplementedError
        elif res_type == 'AWS::Route53::RecordSetGroup':
            raise NotImplementedError
        elif res_type == 'AWS::S3::Bucket':
            bucketname = "MyS3Bucket" # TODO: Random buckets are possible!
            randomness = True
            if res:
                if 'Properties' in res and 'BucketName' in res['Properties']:
                    bucketname = res['BucketName']
                    randomness = False
            else:
                confident = False
            bucketref = '%s-%s-%s' % (stack_name, bucketname, self.gen_alnumchars(12, False))

            return {
                'Ref': {
                    'value': bucketref,
                    'randomness': True
                },
                'Fn::GetAtt': {
                    'Arn': {
                        'value': 'arn:aws:s3:::%s' % (bucketname),
                        'randomness': randomness
                    },
                    'DomainName': {
                        'value': '%s.s3.amazonaws.com' % (bucketref),
                        'randomness': True
                    },
                    'DualStackDomainName': {
                        'value': '%s.s3.dualstack.%s.amazonaws.com' % (bucketref, region),
                        'randomness': True
                    },
                    'WebsiteURL': {
                        'value': 'http://%s.s3-website-%s.amazonaws.com/' % (bucketref, region),
                        'randomness': True
                    }
                }
            }
        elif res_type == 'AWS::S3::BucketPolicy':
            raise NotImplementedError
        elif res_type == 'AWS::SDB::Domain':
            raise NotImplementedError
        elif res_type == 'AWS::SNS::Subscription':
            raise NotImplementedError
        elif res_type == 'AWS::SNS::Topic':
            confident = True
            topicname = "MyTopicName"
            if res:
                if 'Properties' in res and 'TopicName' in res['Properties']:
                    topicname = res['TopicName']
            else:
                confident = False
            
            return {
                'Ref': {
                    'value' : 'arn:aws:sns:%s:%s:%s-%s-%s' % (region, accountid, stack_name, topicname, self.gen_alnumchars(12, True)),
                    'randomness': True
                },
                'Fn::GetAtt': {
                    'TopicName': {
                        'value': topicname,
                        'randomness': False
                    }
                }
            }
        elif res_type == 'AWS::SNS::TopicPolicy':
            raise NotImplementedError
        elif res_type == 'AWS::SQS::Queue':
            raise NotImplementedError
        elif res_type == 'AWS::SQS::QueuePolicy':
            raise NotImplementedError
        elif res_type == 'AWS::SSM::Association':
            raise NotImplementedError
        elif res_type == 'AWS::SSM::Document':
            raise NotImplementedError
        elif res_type == 'AWS::SSM::MaintenanceWindow':
            raise NotImplementedError
        elif res_type == 'AWS::SSM::MaintenanceWindowTarget':
            raise NotImplementedError
        elif res_type == 'AWS::SSM::MaintenanceWindowTask':
            raise NotImplementedError
        elif res_type == 'AWS::SSM::Parameter':
            raise NotImplementedError
        elif res_type == 'AWS::SSM::PatchBaseline':
            raise NotImplementedError
        elif res_type == 'AWS::StepFunctions::Activity':
            raise NotImplementedError
        elif res_type == 'AWS::StepFunctions::StateMachine':
            raise NotImplementedError
        elif res_type == 'AWS::WAF::ByteMatchSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAF::IPSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAF::Rule':
            raise NotImplementedError
        elif res_type == 'AWS::WAF::SizeConstraintSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAF::SqlInjectionMatchSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAF::WebACL':
            raise NotImplementedError
        elif res_type == 'AWS::WAF::XssMatchSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAFRegional::ByteMatchSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAFRegional::IPSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAFRegional::Rule':
            raise NotImplementedError
        elif res_type == 'AWS::WAFRegional::SizeConstraintSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAFRegional::SqlInjectionMatchSet':
            raise NotImplementedError
        elif res_type == 'AWS::WAFRegional::WebACL':
            raise NotImplementedError
        elif res_type == 'AWS::WAFRegional::WebACLAssociation':
            raise NotImplementedError
        elif res_type == 'AWS::WAFRegional::XssMatchSet':
            raise NotImplementedError
        elif res_type == 'AWS::WorkSpaces::Workspace':
            raise NotImplementedError
        else:
            raise NotImplementedError
