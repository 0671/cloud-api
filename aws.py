import json
from IPy import IP
import boto3
import urllib3
urllib3.disable_warnings()
from datetime import datetime, timedelta, date

class DateEncoder(json.JSONEncoder):  
    def default(self, obj):  
        if isinstance(obj, datetime):  
            return obj.strftime('%Y-%m-%d %H:%M:%S')  
        elif isinstance(obj, date):  
            return obj.strftime("%Y-%m-%d")  
        else:  
            return json.JSONEncoder.default(self, obj) 


class awsClient:
    def __init__(self,key_id,key_secret,region_name) -> None:
        self.origin_region_name =region_name
        self.origin_key_id = key_id
        self.origin_key_secret = key_secret
        self.page_size = 100
        self.source = 'AWS'
        self.service_provider = 'AWS'
        self.ec2_region_list = []
        self.client = {}

        self.InitClient()
    
    def InitClient(self,ctype = 'ec2'):
        if ctype in ('ec2','route53','s3','iam','cloudtrail'):
           self.client[ctype] = boto3.client(
            ctype,
            aws_access_key_id=self.origin_key_id,
            aws_secret_access_key=self.origin_key_secret,
            region_name= self.origin_region_name,
            verify=False
            )
        else:
            assert Exception('bad ctype')

    def GetEc2RegionList(self):
        if len(self.ec2_region_list)==0:
            self.InitClient(ctype='ec2')
            response = self.client['ec2'].describe_regions()
            ec2_region_list = [i for i in response['Regions']]
            self.ec2_region_list = ec2_region_list
        return self.ec2_region_list

    def GetIamUser(self):
        all_user_accesskey_dict = {}
        self.InitClient(ctype='iam')
        response = self.client['iam'].list_users()
        for user_data in response['Users']:
            # print(f'...check {user_data["Arn"]}')
            user_id = user_data["UserId"]
            user_name = user_data["UserName"]
            arn = user_data["Arn"]
            create_date = user_data["CreateDate"]
            password_last_used = user_data.get("PasswordLastUsed","") # 未使用就没有该key

            # 获取用户的access_key
            user_accesskey_list = []
            accesskey_mtadata = self.client['iam'].list_access_keys( UserName=user_name)['AccessKeyMetadata']
            user_accesskey_list = [i['AccessKeyId'] for i in accesskey_mtadata]
            all_user_accesskey_dict.update(
                {i:user_name for i in user_accesskey_list}
            )
            if len(user_accesskey_list)==0:
                flag_have_ak = False
            else:
                flag_have_ak = True
            
            # 获取用户所在的组
            user_groups = [i['GroupName'] for i in self.client['iam'].list_groups_for_user(UserName=user_name)['Groups']]

            policy_arns = []
            user_policy_names = []
            group_policy_names = []
            
            for group_name in user_groups:
                # 获取用户组所用托管策略
                policy_arns.extend( [ i['PolicyArn'] for i in self.client['iam'].list_attached_group_policies(GroupName=group_name)['AttachedPolicies']] )
                # 获取用户组所用内联策略
                group_policy_names.extend( [ {'group_name':group_name,'policy_name':i} for i in self.client['iam'].list_group_policies(GroupName=group_name)['PolicyNames']] )

            # 获取用户所用托管策略
            policy_arns.extend( [ i['PolicyArn'] for i in self.client['iam'].list_attached_user_policies(UserName=user_name)['AttachedPolicies']] )              
            # 获取用户所用内联策略
            user_policy_names.extend( [ i for i in self.client['iam'].list_user_policies(UserName=user_name)['PolicyNames']] )

            policy_documents = {}
            # 获取策略细节
            # 获取托管策略
            for pa in policy_arns:
                response = self.client['iam'].get_policy( PolicyArn=pa )
                policy = response["Policy"]
                default_version_id = policy["DefaultVersionId"]
                response = self.client['iam'].get_policy_version(    PolicyArn=pa, VersionId=default_version_id)
                policy_document = response["PolicyVersion"]["Document"]
                if type(policy_document['Statement'])!=list:
                    policy_document['Statement'] = [ policy_document['Statement'] ]
                policy_documents[pa]=policy_document

           
           # 获取用户的内联策略
            for pn in user_policy_names:
                response = self.client['iam'].get_user_policy( UserName= user_name, PolicyName=pn )
                policy_document = response["PolicyDocument"]
                if type(policy_document['Statement'])!=list:
                    policy_document['Statement'] = [ policy_document['Statement'] ]
                policy_documents[pa]=policy_document

            # 获取用户组的内联策略
            for pn in group_policy_names:
                group_name = pn['group_name']
                policy_name = pn['policy_name']
                response = self.client['iam'].get_group_policy( GroupName= group_name, PolicyName=policy_name )
                policy_document = response["PolicyDocument"]
                if type(policy_document['Statement'])!=list:
                    policy_document['Statement'] = [ policy_document['Statement'] ]
                policy_documents[pa]=policy_document

            # 分析策略
            access_ip_list = []
            flag_dangerour_action = False
            for pa in policy_documents:
                statement = policy_documents[pa]['Statement']
                for s in statement:
                    # 判断是否有访问ip限制
                    if s["Effect"]=='Deny' and s['Action']=='*' and s['Resource']=='*':
                        if 'Condition' in s and 'NotIpAddress' in s['Condition'] and 'aws:SourceIp' in s['Condition']['NotIpAddress']:
                            access_ip_list = s['Condition']['NotIpAddress']['aws:SourceIp']
                    
                    # 判断是否敏感操作限制
                    danger_statement_list = [
                        {
                            # 允许来自任何 AWS 账户的任何 IAM 用户在您的账户中代入角色
                            'Effect':'Allow',
                            'Principal':'*',
                            'Action':'sts:AssumeRole',
                        },
                        {
                            # 允许任何操作
                            'Effect':'Allow',
                            'Action':'*',
                            'Resource':'*'
                        },
                    ] # 敏感操作表
                    for ds in danger_statement_list:
                        match_ds = all([s.get(k,None)==ds[k] for k in ds])
                        if match_ds==True:
                            flag_dangerour_action = True
            
            if len(access_ip_list)==0:
                flag_any_ip_access = True
            else:
                flag_any_ip_access = False
            
            access_ip_list =   ", ".join(access_ip_list)
            bad_desc_list = []
            normal_desc_list = []
            good_desc_list = []
            if flag_have_ak:
                normal_desc_list.append(f'存在AccessKey {len(user_accesskey_list)}个') 
            if flag_any_ip_access:
                bad_desc_list.append(f'!未限制ip访问')
            else:
                good_desc_list.append(f'限制指定ip访问: {access_ip_list:.<25.22}')
            if flag_dangerour_action:
                normal_desc_list.append(f'拥有危险权限')
            desc_list = bad_desc_list+normal_desc_list+good_desc_list
            if len(bad_desc_list)>0:
                print(f'【×】用户 {user_name} '+ ', '.join(desc_list))
            else:
                print(f'【√】用户 {user_name} '+ ', '.join(desc_list))

        # 审计 AccessKey 调用的 ip/action
        print(f'审计所有 AccessKey({len(all_user_accesskey_dict)}) 的事件')
        all_user_accesskey_list = sorted(all_user_accesskey_dict.items(), key=lambda item:item[1]) # 排序dict，得到一个 2个元素的元组的list
        self.CheckBadIpOfDangerousCallByAccessKey(all_user_accesskey_list)
    
    def CheckBadIpOfDangerousCallByAccessKey(self, all_user_accesskey_list=[]):
        '''
            审计AWS的Accesskey的调用ip、执行动作
        '''
        
        check_hour=10 # 查询日志时间范围，此处意思为 10小时内
        check_region_list  = [] # 查询的可用区范围，如果为空，则查询全部可用区

        white_ip_list = [
            '192.168.1.0/24',
            # '192.168.1.0/24',
        ] # 白名单ip列表
        white_ip_obj_list = [
            IP(ip,make_net=True)  for ip in white_ip_list
        ] # 白名单ip对象列表
        dangerous_event_list = [
            'CreateUser', # 创建用户
            'ListUsers', # 列用户
            'ListBuckets', # 列s3的bucket
            'AttachUserPolicy', # 用户关联策略
            'CreateSecurityGroup', # 创建安全组
            'AuthorizeSecurityGroupIngress', # 修改安全组的入站规则
        ] # 危险调用事件列表

        def check_event_ip_while(ip,white_ip_obj_list=white_ip_obj_list):
            ip = IP(ip,make_net=True)
            for wip_obj in white_ip_obj_list:
                if ip in wip_obj:
                    return True
            return False
            
        def check_event_action_dangerous(event,dangerous_event_list=dangerous_event_list):
            if event in dangerous_event_list:
                return True
            else:
                return False

        end_time = datetime.now() 
        start_time = end_time+timedelta(hours= -check_hour )
        ip_event_name_list = {} # ip映射事件表
        bad_ip_call_dangerous_event_list = {} # 异常ip调用危险事件映射表

        region_list = [ region['RegionName'] for region in self.GetEc2RegionList()] if len(check_region_list)==0 else check_region_list

        for region_name in region_list:
            self.origin_region_name = region_name
            self.InitClient('cloudtrail')
            paginator = self.client['cloudtrail'].get_paginator('lookup_events')
            print(f'check region {region_name}')
            for user_accesskey in all_user_accesskey_list:
                accesskey, user_name = user_accesskey
                # 获取acceesskey调用事件
                page_iterator = paginator.paginate(
                    LookupAttributes=[
                        {'AttributeKey': 'AccessKeyId', 'AttributeValue': accesskey},
                    ],
                    StartTime=start_time,
                    EndTime=end_time,) 
                n = 0
                n_max=10000 # 最多读取10000个日志
                for page in page_iterator:
                    n = n+len(page['Events'])
                    if n > n_max:
                        break
                    for event in page['Events']:
                        cloud_trail_event = json.loads(event['CloudTrailEvent'])
                        request_parameters = cloud_trail_event["requestParameters"]
                        response_elements = cloud_trail_event["responseElements"]
                        event_name = event['EventName']
                        source_ip_address = cloud_trail_event['sourceIPAddress']
                        user_agent = cloud_trail_event['userAgent']

                        if 'aws-internal' not in user_agent and check_event_ip_while(source_ip_address)==False:
                            if check_event_action_dangerous(event_name)==True:
                                if source_ip_address not in bad_ip_call_dangerous_event_list:
                                    bad_ip_call_dangerous_event_list[source_ip_address] = {event_name}
                                else:
                                    bad_ip_call_dangerous_event_list[source_ip_address].add(event_name)
                        if source_ip_address not in ip_event_name_list:
                            ip_event_name_list[source_ip_address] = {event_name}
                        else:
                            ip_event_name_list[source_ip_address].add(event_name)

                if len(ip_event_name_list)==0:
                    print(f'user:{user_name}--{accesskey} {region_name} {str(start_time) :.19}-{str(end_time) :.19} 无访问 ')
                else:
                    print(f'user:{user_name}--{accesskey} {region_name} {str(start_time) :.19}-{str(end_time) :.19} 访问情况: ')
                    print('\n'.join([f'\t{ip}: {list(ip_event_name_list[ip])}' for ip in ip_event_name_list]))
                    if len(bad_ip_call_dangerous_event_list)>0:
                        print(f'【×】user:{user_name}--{accesskey} {region_name} {str(start_time) :.19}-{str(end_time) :.19} 异常ip调用危险动作情况: ')
                        print('\n'.join([f'\t{ip}: {list(bad_ip_call_dangerous_event_list[ip])}' for ip in bad_ip_call_dangerous_event_list]))           

    def GetVpcList(self):
        vpc_list = {}
        region_list = self.GetEc2RegionList()
        for region in region_list:
            region_name = region['RegionName']
            self.origin_region_name = region_name
            self.InitClient()
            response = self.client['ec2'].describe_vpcs()
            for vpc_data in response['Vpcs']:
                vpc = {}
                vpc.update(owner_id=vpc_data['OwnerId'])
                vpc.update(vpc_id=vpc_data['VpcId'])
                vpc.update(cidr_block=vpc_data['CidrBlock'])
                vpc.update(is_default=vpc_data['IsDefault'])
                vpc.update(state=vpc_data['State'])
                vpc_list[vpc_data.get('VpcId')]=vpc
        return vpc_list


    def GetSubnetList(self):
        subnet_list = {}
        region_list = self.GetEc2RegionList()
        region_list = region_list[:4]
        for region in region_list:
            region_name = region['RegionName']
            self.origin_region_name = region_name
            self.InitClient()
            response = self.client['ec2'].describe_subnets()
            for sn_data in response['Subnets']:
                subnet = {}
                subnet.update(owner_id=sn_data['OwnerId'])
                subnet.update(subnet_id=sn_data['SubnetId'])
                subnet.update(vpc_id=sn_data['VpcId'])
                subnet.update(cidr_block=sn_data['CidrBlock'])
                subnet.update(state=sn_data['State'])
                subnet_list[subnet.get('subnet_id')]=subnet
        return subnet_list

    def GeNetworkAclList(self):
        network_acl_list = {}
        region_list = self.GetEc2RegionList()
        for region in region_list:
            region_name = region['RegionName']
            self.origin_region_name = region_name
            self.InitClient()
            response = self.client['ec2'].describe_network_acls()
            for acl_data in response['NetworkAcls']:
                network_acl = {}
                network_acl.update(owner_id=acl_data['OwnerId'])
                network_acl.update(owner_id=acl_data['OwnerId'])
                network_acl.update(network_acl_id=acl_data['NetworkAclId'])
                network_acl.update(vpc_id=acl_data['VpcId'])
                network_acl.update(is_default=acl_data['IsDefault'])
                network_acl.update(egress_entries=[i for i in acl_data['Entries'] if i["Egress"]==True]) # 出口规则
                network_acl.update(ingress_entries=[i for i in acl_data['Entries'] if i["Egress"]==False]) # 入口规则
                network_acl.update(subnet_id_list=[i['SubnetId'] for i in acl_data['Associations']]) # 关联子网id列表
                network_acl_list[network_acl.get('network_acl_id')]=network_acl
        return network_acl_list


    def GetSecurityGroupRuleList(self):
        security_group_rule_list = {}

        region_list = self.GetEc2RegionList()
        for region in region_list:
            region_name = region['RegionName']
            self.origin_region_name = region_name
            self.InitClient()
            response = self.client['ec2'].describe_security_groups()

            for sg in response['SecurityGroups']:
                if sg['GroupId'] in ['sg-08cd32147c3ec8f9e','sg-03e5e0fcb88d58f76']:
                    print(sg)
                    exit()
                _sg = {}

                _sg.update(sg_id=sg['GroupId'])
                _sg.update(sg_name=sg['GroupName'])
                _sg.update(owner_id=sg['OwnerId'])
                _sg.update(desc=sg['Description'])
                _sg.update(in_rule_list=[])
                _sg.update(out_rule_list=[])

                for in_rule in sg['IpPermissions']:
                    if in_rule.get('FromPort','None')=='None':
                        continue # 默认的入站规则
                    _in_rule = {}
                    _in_rule['port_range'] = f"{in_rule.get('FromPort')}-{in_rule.get('ToPort')}"
                    _in_rule['port_protocol'] = in_rule.get('IpProtocol')
                    _in_rule['source_list'] = [i.get('CidrIp') for i in in_rule.get('IpRanges',{})]
                    _sg['in_rule_list'].append(_in_rule)
                
                for out_rule in sg['IpPermissionsEgress']:
                    _out_rule = {}
                    _out_rule['port_protocol'] = out_rule.get('IpProtocol')
                    _out_rule['target_list'] = [i.get('CidrIp') for i in out_rule.get('IpRanges',{})]
                    _sg['out_rule_list'].append(_out_rule)
                
                security_group_rule_list[sg['GroupId']]=_sg

        return security_group_rule_list


    def GetInstanceList(self):
        instance_list = {}
        region_list = self.GetEc2RegionList()
        for region in region_list:
            region_name = region['RegionName']
            self.origin_region_name = region_name
            self.InitClient()
            response = self.client['ec2'].describe_instances()
            for inst_res in response['Reservations']:
                owner_id = inst_res['OwnerId']
                for ins in inst_res['Instances']:
                    instance = {}
                    instance.update(instance_id=ins.get('InstanceId'))
                    instance.update(instance_name=ins.get('KeyName'))
                    instance.update(public_ip=ins.get('PublicIpAddress',''))
                    instance.update(private_ip=ins.get('PrivateIpAddress',''))
                    instance.update(instance_tags=ins.get('Tags', ''))
                    instance.update(region_id=region_name)
                    instance.update(instance_status=ins['State']['Name'])
                    instance.update(security_group_ids=[i['GroupId'] for i in ins['SecurityGroups']])
                    instance.update(owner_id=owner_id)
                    instance_list[ins.get('InstanceId')]=instance
        return instance_list

    def GetDnsRecordList(self):
        dns_record_list = {}
        self.InitClient(ctype='route53')

        marker = ''
        _zone_list=[]
        while True:
            response = self.client['route53'].list_hosted_zones(
                Marker=marker,
                MaxItems='100'
            )
            _zone_list.extend(response['HostedZones'])
            if response['IsTruncated']==False:
                break
            else:
                marker = response['NextMarker']

        _dns_record_list = []

        for _zone in _zone_list:
            next_record_name = ''
            next_record_type = ''
            hostedzone_id = _zone['id']
            while True:
                response = self.client['route53'].list_resource_record_sets(
                    HostedZoneId=hostedzone_id,
                    StartRecordName=next_record_name,
                    StartRecordType=next_record_type,
                    MaxItems='300'
                )
                _dns_record_list.extend(response['ResourceRecordSets'])
                if response['IsTruncated']==False:
                    break
                else:
                    next_record_name = response['NextRecordName']
                    next_record_type = response['NextRecordType']
        
        for dr in _dns_record_list:
            #todo 处理dns——record
            pass
        return dns_record_list
                

    def GetOssList(self):
        oss_list = []
        self.InitClient(ctype='s3')
        response = self.client['s3'].list_buckets()
        for bucket in response['Buckets']:
            _oss = {}
            name = bucket['Name']
            bucket_location = self.client['s3'].get_bucket_location( Bucket=name )['LocationConstraint']
            url = f'https://{name}.s3.{bucket_location}.amazonaws.com/'
            
            try:
                policy_status = self.client['s3'].get_bucket_policy_status( Bucket=name)['PolicyStatus']
                grant = 'public' if policy_status['IsPublic']==True else 'private'
            except Exception as e:
                grant = ''
            try:
                policy = self.client['s3'].get_bucket_policy( Bucket=name)['Policy']
            except Exception as e:
                policy = {}
            try:
                owner_id =  self.client['s3'].get_bucket_acl( Bucket=name)['Owner']['ID']
            except Exception as e:
                owner_id = ''
            _oss.update(name= name )
            _oss.update(url= url )
            _oss.update(grant= grant)
            _oss.update(policy= policy) 
            _oss.update(owner_id=owner_id)
            
            oss_list.append(_oss)
        return oss_list

if __name__=='__main__':
    key_list = [
        {"KeyId":"AK...","KeySecret":"...","Remark":"..."},
    ]
    for i in key_list:
        test=awsClient(
            key_id=i['KeyId'],
            key_secret=i['KeySecret'],
            region_name='ap-southeast-1')
        test.GetIamUser()
