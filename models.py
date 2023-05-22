import base64
import boto3
import html2markdown
import json
import logging
import math
import os
import pandas as pd
import shutil
import tempfile
import time

from botocore.exceptions import ClientError
from datetime import date
from datetime import datetime, timedelta
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.template.loader import get_template
from django.utils.timezone import now, localtime
from io import BytesIO
from jinja2 import Template
from requests import request
from tempfile import TemporaryDirectory
from uuid import uuid4
from weasyprint import HTML

# Create your models here.
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from geekapp.utils import encrypt, decrypt, bprencrypt

# import io
# from django.core.files.base import ContentFile

from companies.models import Company
from qualys.models import Qualys
from tags.models import Tag
from io import BytesIO

ABP_HEADER = {
    'X-Requested-With': 'App API Authentication',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    "retreiver": settings.RETREIVER
}

SSM_CLIENT = boto3.client('ssm', region_name=settings.AWS_REGION_NAME)

class AWSCISFramework(object):
    def cis_1_7_check(self, data):
        if data['access_key_2_active']["0"] == True or \
            data['access_key_1_active']["0"] == True or \
            datetime.strptime(data['password_last_used']["0"],'%Y-%m-%dT%H:%M:%S+00:00') >= datetime.now() - timedelta(days=15):
            return 'cis_1_7'
        return None

    def cis_1_8_check(self, data):
        '''
        password_policy
        MinimumPasswordLength
        '''
        if data["MinimumPasswordLength"] < 14:
            return 'cis_1_8'
        return None

    def cis_1_9_check(self, data):
        '''
        PasswordReusePrevention >= 24

        '''
        if 'MinimumPasswordLength' in data and data["MinimumPasswordLength"] >= 24:
            return None
        return 'cis_1_9'

    def cis_1_10_check(self, data):
        '''
        mfa_active == true if password_enabled == true
        '''
        for key in data['password_enabled']:
            if data['password_enabled'][key] in ["true", True] and data['mfa_active'][key] != True:
                return 'cis_1_10'
                break
        return None

    def cis_1_11_check(self, data):
        '''
        cred_report
        user_creation_time != access_key_creation time
        '''
        # for key in data['password_enabled']:
        #     if data['password_enabled'][key] in ["true", True] and data['mfa_active'][key] != True:
        #         return 'cis_1_10'
        return None

    def cis_1_12_check(self, data):
        '''
        cred_report
        access_key_1_active != access_key_creation time
        '''
        for key in data['access_key_1_active']:
            if data['access_key_1_active'][key] == True and data['access_key_1_last_used_date'][key] is not None and\
                datetime.strptime(data['access_key_1_last_used_date'][key],'%Y-%m-%dT%H:%M:%S+00:00') >= datetime.now() - timedelta(days=90):
                return 'cis_1_12'
        for key in data['access_key_2_active']:
            if data['access_key_2_active'][key] == True and data['access_key_2_last_used_date'][key] is not None and \
                datetime.strptime(data['access_key_2_last_used_date'][key],'%Y-%m-%dT%H:%M:%S+00:00') >= datetime.now() - timedelta(days=90):
                return 'cis_1_12'
        return None

    def cis_1_13_check(self, data):
        '''
        Description:
        Access keys are long-term credentials for an IAM user or the AWS account root user. You can use access keys to sign programmatic requests to the AWS CLI or AWS API (directly or using the AWS SDK)

        Rationale:
        Access keys are long-term credentials for an IAM user or the AWS account root user. You can use access keys to sign programmatic requests to the AWS CLI or AWS API. One of the best ways to protect your account is to not allow users to have multiple access keys.
        cred_report

        access_key_1_active != access_key_creation time
        '''
        for key in data['access_key_1_active']:
            if data['access_key_1_active'][key] == True and data['access_key_2_active'][key] == True:
                return 'cis_1_13'
        return None

    def cis_1_14_check(self, data):
        '''
        Description:
        Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests that you make to AWS. AWS users need their own access keys to make programmatic calls to AWS from the AWS Command Line Interface (AWS CLI), Tools for Windows PowerShell, the AWS SDKs, or direct HTTP calls using the APIs for individual AWS services. It is recommended that all access keys be regularly rotated.

        Rationale:
        Rotating access keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used.
        Access keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen.

        access_key_1_active != access_key_creation time
        '''
        for key in data['access_key_1_active']:
            if data['access_key_1_active'][key] == True and data['access_key_1_last_used_date'][key] is not None and\
                datetime.strptime(data['access_key_1_last_used_date'][key],'%Y-%m-%dT%H:%M:%S+00:00') >= datetime.now() - timedelta(days=90):
                return 'cis_1_14'
        for key in data['access_key_2_active']:
            if data['access_key_2_active'][key] == True and data['access_key_2_last_used_date'][key] is not None and \
                datetime.strptime(data['access_key_2_last_used_date'][key],'%Y-%m-%dT%H:%M:%S+00:00') >= datetime.now() - timedelta(days=90):
                return 'cis_1_14'
        return None

    def cis_1_15_check(self, data):
        # print(data)
        if len(data) > 0:
            return 'cis_1_15'
        return None

    def cis_n_check(self, data, n="cis_1_16"):
        # print(data)
        if len(data) > 0:
            return n
        return None

    def cis_1_19_check(self, data):
        # print(data)
        if len(data) > 0:
            return 'cis_1_19'
        return None

    def cis_1_20_check(self, data):
        # print(data)
        if len(data) > 0:
            return 'cis_1_20'
        return None

    def cis_1_21_check(self, data):
        # print(data)
        if len(data) == 0:
            return 'cis_1_21'
        return None


class BestPracticeReview(models.Model):
    '''
    WAS Report
    /qps/rest/3.0/count/was/webapp
    '''
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    qualys = models.ForeignKey(
        Qualys, on_delete=models.CASCADE,
        blank=True, null=True
    )
    company = models.ForeignKey(
        Company, on_delete=models.CASCADE,
        blank=True, null=True)
    uuid = models.CharField(max_length=225, blank=True, default='')
    temp_token = models.CharField(max_length=225, blank=True, default='')
    redirect_url = models.CharField(max_length=225, blank=True, default='')
    temp_token_created_at = models.DateTimeField(null=True, blank=True)
    connection_data = models.TextField(blank=True, null=True, default='{}')
    az_text = models.TextField(blank=True, null=True, default='')
    last_scanned_at = models.DateTimeField(auto_now_add=True)
    archived = models.BooleanField(default=False, blank=True)
    CLOUD_PROVIDERS = (('AWS', 'AMAZON WEB SERVICES'),('AZURE', 'AZURE'),)
    source_type = models.CharField(default='AWS', choices=CLOUD_PROVIDERS, blank=True, max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    cost = models.CharField(default='$0', blank=True, max_length=10)
    STATUSES = (
        ('connecting', 'CONNECTING'),
        ('connected', 'CONNECTED'),
        ('scanning', 'SCANNING'),
        ('scanned', 'SCANNED'),
        ('disconnected', 'DISCONNECTED'),
    )
    account_name = models.CharField(max_length=225, blank=True, default='')
    account_id = models.CharField(max_length=225, blank=True, default='')
    is_active = models.BooleanField(blank=True, default=True)
    conn_type = models.CharField(default='connecting', choices=STATUSES, blank=True, max_length=20)
    compute_saving = models.TextField(blank=True, null=True, default=None)
    ec2_saving = models.TextField(blank=True, null=True, default=None)
    scan_start_time = models.CharField(max_length=512, blank=True, default='')
    scan_end_time = models.CharField(max_length=512, blank=True, default='')

    def start_scan(self):
        self.conn_type = 'scanning'
        self.scan_start_time = '{}'.format(time.time())
        self.save()

    def end_scan(self):
        self.conn_type = 'scanned'
        self.scan_end_time = '{}'.format(time.time())
        self.save()

    def __str__(self):
        return super().__str__()

    def save(self, *args, **kwargs):
        if self.uuid is None or self.uuid == "":
            self.connect()
        super(BestPracticeReview, self).save(*args, **kwargs)

    def connect(self):
        pass

    class Meta:
        ordering = ('-id',)
        abstract = True


class AWSBestPracticeReview(BestPracticeReview):
    def connect(self):
        if self.uuid is None or self.uuid == "":
            self.uuid = str(uuid4())
            self.temp_token = str(uuid4())
        if self.source_type == 'AZURE':
            self.connect_azure()
        elif self.source_type == 'AWS':
            self.connect_aws()

    def connect_azure(self):
        url = '{}/connections/azure/'.format(settings.ABP_FRAMEWORK_URL)
        headers = ABP_HEADER
        payload = {
            "text": self.az_text,
            "redirect_uri": self.redirect_url,
            "retreiver": settings.RETREIVER
        }
        response = request("POST", url, headers=headers, data=json.dumps(payload))
        self.conn_type = 'connected'
        if response.status_code != 200:
            self.deactivate()
        data = response.json()
        if 'statusCode' in data and data['statusCode'] not in [200, 201]:
            self.deactivate()
        if 'subscriptions' in data and 'value' in data['subscriptions']:
            for subs in data['subscriptions']['value']:
                if AWSBestPracticeReview.objects.filter(
                    source_type='AZURE',
                    account_id = subs['subscriptionId']
                ).count() > 0:
                    raise ValueError('It seems the connection already exists.')
                if self.account_id is None or self.account_id == '':
                    self.account_id = subs['subscriptionId']
                    self.account_name = subs['displayName']
                else:
                    bpa = AWSBestPracticeReview.objects.create(
                        account_id=subs['subscriptionId'],
                        company=self.company,
                        source_type='AZURE',
                        conn_type='scanning',
                        account_name=subs['displayName'],
                        is_active=True,
                        uuid=str(uuid4()),
                        temp_token = self.temp_token,
                        az_text=self.az_text,
                        redirect_url=self.redirect_url,
                        user=self.user,
                        qualys=self.qualys,
                    )
        else:
            raise ValueError(
                'Please check the permissions. \
                We are unable to fetch the subscription information.'
            )
        self.connection_data = json.dumps(data)
        return self.connection_data

    def deactivate(self):
        self.conn_type = 'disconnected'
        # self.archived = True
        self.is_active = False
        raise ValueError('Connection could not be established.')

    def connect_aws(self):
        url = settings.ABP_FRAMEWORK_URL+'/connections/'#.format(qualys.api_url)
        headers = ABP_HEADER
        payload = {
            "id": self.uuid,
            "text": self.uuid,
            "retreiver": settings.RETREIVER
        }
        response = request("POST", url, headers=headers, data=json.dumps(payload))
        self.conn_type = 'connected'
        print('Status Code: ', response.status_code)
        if response.status_code != 200:
            self.deactivate()
        data = response.json()
        if 'statusCode' in data and data['statusCode'] not in [200, 201]:
            self.deactivate()
        self.connection_data = json.dumps(data)
        '''
        Below call need to wait till connection is confirmed
        '''
        # try:
        #     self.get_realtime_data(return_type='o-decrypt')
        # except Exception as e:
        #     print(e)
        #     raise ValueError('Unable to fetch Account Information. It seems account used to connect does not have permission to read account information.')
        return self.connection_data

    def add_access_key(self, token):
        encrypted_data = bprencrypt(token)
        text = encrypted_data['ciphertext']
        tag = encrypted_data['tag']
        url = settings.ABP_FRAMEWORK_URL+'/keys/'#.format(qualys.api_url)
        headers = ABP_HEADER
        payload = {
            'text': text,
            'key': tag,
            'uuid': self.uuid
        }
        response = request("POST", url, headers=headers, data=json.dumps(payload))
        # if response.status_code != 200:
        #     self.deactivate()
        return True

    def fetch_findings(self):
        if self.source_type == 'AZURE':
            self.fetch_azure_findings()
        elif self.source_type == 'AWS':
            self.fetch_aws_findings()

    def fetch_aws_findings(self):
        self.start_scan()
        self.get_realtime_data('o-decrypt')
        self.get_realtime_data('i-decrypt')
        self.get_realtime_data('s-decrypt')
        self.get_realtime_data('e-decrypt')
        # self.get_realtime_data('ebs-decrypt')
        # self.get_realtime_data('r-decrypt')
        # self.get_realtime_data('rs-decrypt')
        self.get_realtime_data('t-decrypt')
        self.get_realtime_data('ce-decrypt')
        self.get_realtime_data('n-decrypt')
        self.get_realtime_data('l-decrypt')
        self.get_realtime_data('m-decrypt')
        self.end_scan()

    def fetch_azure_findings(self):
        pass

    def get_realtime_data(self, return_type='', fetch_archived=False):
        # if self.archived == True and fetch_archived == False:
        #     return {}

        url = settings.ABP_FRAMEWORK_URL
        headers = ABP_HEADER
        data = {}
        if return_type != '':
            url += '/keys/scan/{}/{}'.format(
                self.uuid,
                # '4a14c62b-084f-4e9e-a5d8-849162d38ea9',
                return_type
            )
            response = request("GET", url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                # if 'statusCode' in data and data['statusCode'] not in [200, 201]:
                #     self.deactivate()
                self.is_active = True
                if return_type == 'i-decrypt':
                    self.generate_org_report(data=data)
                    self.generate_password_report(data=data)
                    self.generate_iam_report(data=data)
                    self.conn_type = 'scanned'
                elif return_type == 'o-decrypt':
                    self.generate_org_report(data=data)
                elif return_type == 's-decrypt':
                    self.generate_s3_report(data=data)
                elif return_type == 'e-decrypt':
                    self.generate_ec2_report(data=data)
                elif return_type == 'l-decrypt':
                    self.generate_logging_report(data=data)
                elif return_type == 'n-decrypt':
                    self.generate_network_report(data=data)
                elif return_type == 'm-decrypt':
                    self.generate_monitoring_report(data=data)
                elif return_type == 'ce-decrypt':
                    self.ec2_saving = data['recommendations']['ec2']
                    self.compute_saving = data['recommendations']['compute']
                    _data = {
                        'total_savings': 0,
                        'ec2': {},
                        'compute': {},
                    }
                    self.cost = 0.0
                    for key in data['recommendations']['ec2']['SavingsPlansPurchaseRecommendation']:
                        if key != 'SavingsPlansPurchaseRecommendationDetails':
                            _data['ec2'][key] = data['recommendations']['ec2']['SavingsPlansPurchaseRecommendation'][key]
                            if key == 'SavingsPlansPurchaseRecommendationSummary':
                                self.cost += float(data['recommendations']['ec2']['SavingsPlansPurchaseRecommendation']['SavingsPlansPurchaseRecommendationSummary']['EstimatedMonthlySavingsAmount'])
                    for key in data['recommendations']['compute']['SavingsPlansPurchaseRecommendation']:
                        if key != 'SavingsPlansPurchaseRecommendationDetails':
                            _data['compute'][key] = data['recommendations']['compute']['SavingsPlansPurchaseRecommendation'][key]
                            if key == 'SavingsPlansPurchaseRecommendationSummary':
                                self.cost += float(data['recommendations']['compute']['SavingsPlansPurchaseRecommendation']['SavingsPlansPurchaseRecommendationSummary']['EstimatedMonthlySavingsAmount'])
                    self.cost = '$'+ str(round(self.cost, 2))
                    _data['total_savings'] = self.cost
                    data = _data
            else:
                # self.is_active = False
                # self.conn_type = 'disconnected'
                print('Error: Data is not valid', response.status_code)
        return data

    def generate_access_key_report(self, data={'cred_report': {}}):
        # Avoid the use of the "root" account
        policy = data['cred_report']
        access_key_1_active = policy['access_key_1_active']
        access_key_1_last_rotated = policy['access_key_1_last_rotated']
        access_key_1_last_used_date = policy['access_key_1_last_used_date']
        rule_set ={
            # "AccessKeysPerUserQuota": 2,
            "access_key_1_active": {},
            "access_key_1_last_rotated": {},
            # "AccountSigningCertificatesPresent": 0,
            # "AssumeRolePolicySizeQuota": 2048,
            # "AttachedPoliciesPerGroupQuota": 10,
            # "AttachedPoliciesPerRoleQuota": 10,
            # "AttachedPoliciesPerUserQuota": 10,
            # "GlobalEndpointTokenVersion": 1,
            # "GroupPolicySizeQuota": 5120,
            # "Groups": 4,
            # "GroupsPerUserQuota": 10,
            # "GroupsQuota": 300,
            # "InstanceProfiles": 2,
            # "InstanceProfilesQuota": 1000,
            "MFADevices": 1,
            # "MFADevicesInUse": policy['Users'],
            # "Policies": 17,
            # "PoliciesQuota": 1500,
            # "PolicySizeQuota": 6144,
            # "PolicyVersionsInUse": 60,
            # "PolicyVersionsInUseQuota": 10000,
            # "Providers": 1,
            # "RolePolicySizeQuota": 10240,
            # "Roles": 45,
            # "RolesQuota": 1000,
            # "ServerCertificates": 0,
            # "ServerCertificatesQuota": 20,
            # "SigningCertificatesPerUserQuota": 2,
            # "UserPolicySizeQuota": 2048,
            # "Users": 6,
            # "UsersQuota": 5000,
            # "VersionsPerPolicyQuota": 5
        }
        message_set ={
            "AccountAccessKeysPresent": 'Ensure no root account access key exists',
            "AccountMFAEnabled": 'Ensure MFA is enabled for the "root" account',
            "MFADevices": 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password',
            # "MFADevicesInUse": 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password'
        }
        remediation_set ={
            "AccountAccessKeysPresent": '''
            Perform the following to delete or disable active root access keys being Via the AWS Console
            1. Sign in to the AWS Management Console as Root and open the IAM console at https://console.aws.amazon.com/iam/.
            2. Click on <Root_Account_Name> at the top right and select Security Credentials from the drop down list
            3. On the pop out screen Click on Continue to Security Credentials
            4. Click on Access Keys (Access Key ID and Secret Access Key)
            5. Under the Status column if there are any Keys which are Active
            1. Click on Make Inactive - (Temporarily disable Key - may be needed again)
            2. Click Delete - (Deleted keys cannot be recovered)
            ''',
            "AccountMFAEnabled": '''
            Perform the following to establish a hardware MFA for the root account:
            1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            Note: to manage MFA devices for the root AWS account, you must use your root account credentials to sign in to AWS. You cannot manage MFA devices for the root account using other credentials.
            2. Choose Dashboard , and under Security Status , expand Activate MFA on your root account.
            3. Choose Activate MFA
            4. In the wizard, choose A hardware MFA device and then choose Next Step .
            5. In the Serial Number box, enter the serial number that is found on the back of the MFA device.
            6. In the Authentication Code 1 box, enter the six-digit number displayed by the MFA device. You might need to press the button on the front of the device to display the number.
            7. Wait 30 seconds while the device refreshes the code, and then enter the next six-digit number into the Authentication Code 2 box. You might need to press the button on the front of the device again to display the second number.
            8. Choose Next Step .
            The MFA device is now associated with the AWS account. The next time you use your AWS account credentials to sign in, you must type a code from the hardware MFA device.
            ''',
            "MFADevices": '''
            Perform the following to enable MFA:
            1.Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            2.In the navigation pane, choose Users.
            3.In the User Name list, choose the name of the intended MFA user.
            4.Choose the Security Credentials tab, and then choose Manage MFA Device.
            5.In the Manage MFA Device wizard, choose A virtual MFA device, and then choose Next Step.IAM generates and displays configuration information for the virtual MFA device, including a QR code graphic. The graphic is a representation of the 'secret configuration key' that is available for manual entry on devices that do not support QR codes.
            6. Open your virtual MFA application. (For a list of apps that you can use for hosting virtual MFA devices, see Virtual MFA Applications.) If the virtual MFA application supports multiple accounts (multiple virtual MFA devices), choose the option to create a new account (a new virtual MFA device).
            7. Determine whether the MFA app supports QR codes, and then do one of the following:
            Use the app to scan the QR code. For example, you might choose the camera icon or choose an option similar to Scan code, and then use the device's camera to scan the code.
            In the Manage MFA Device wizard, choose Show secret key for manual configuration, and then type the secret configuration key into your MFA application.
            When you are finished, the virtual MFA device starts generating one-time passwords.
            8. In the Manage MFA Device wizard, in the Authentication Code 1 box, type the one-time password that currently appears in the virtual MFA device. Wait up to 30 seconds for the device to generate a new one-time password. Then type the second one-time password into the Authentication Code 2 box. Choose Active Virtual MFA.Forced IAM User Self-Service RemediationAmazon has published a pattern that forces users to self-service setup MFA before they have access to their complete permissions set. Until they complete this step, they cannot access their full permissions. This pattern can be used on new AWS accounts. It can also be used on existing accounts -it is recommended users are given instructions and a grace period to accomplish MFA enrollment before active enforcement on existing AWS accounts.How to Delegate Management of Multi-Factor Authentication to AWS IAM Users
            '''
        }
        for key in rule_set.keys():
            active_or_fixed = 'fixed' if rule_set[key] == policy[key] else 'active'
            finding, created = self.finding_set.get_or_create(
                source_type='bpr',
                severity=3,
                title=message_set[key],
                name=message_set[key],
                bpr=self,
            )
            # print(finding.id, created)
            finding.company = self.company
            finding.qualys = self.company.qualys
            if created == True:
                if rule_set[key] == policy[key]:
                    finding.status = 'FIXED'
                else:
                    finding.status = 'NEW'
                finding.first_detected_date = now()
                finding.last_detected_date = now()
            else:
                if finding.status in ['ACTIVE', 'NEW']:
                    finding.status = 'ACTIVE'
                    finding.last_detected_date = now()
                else:
                    finding.status = 'REOPENED'
                    finding.last_detected_date = now()
            if rule_set[key] == policy[key]:
                finding.status = 'FIXED'
            finding.finding_type = "Cloud BPA"
            finding.group = 'IAM / Security'
            finding.solution = remediation_set[key]
            finding.impact = 'All IAM Users'
            finding.active_or_fixed = active_or_fixed
            finding.last_tested_date = now()

            finding.title = message_set[key]
            finding.name = message_set[key]
            finding.published_datetime = now()
            finding.last_processed_datetime = now()
            finding.last_service_modification_datetime = now()
            finding.save()
        return policy
        # Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password
        return True

    def generate_org_report(self, data={'get_caller_identity': {}}):
        self.account_id = data['get_caller_identity']['Account']
        self.save()
        if self.account_id != None and self.account_id != '':
            connected_accounts = AWSBestPracticeReview.objects.filter(
                source_type='AWS',
                account_id = self.account_id,
                archived=False
            ).order_by('id')
            if connected_accounts.count() > 1:
                true_connection = connected_accounts.first()
                connected_accounts.update(archived=True)
                true_connection.uuid = self.uuid
                self.uuid = str(uuid4())
                true_connection.archived = False
                self.save()
                true_connection.save()
                true_connection.fetch_findings()
                true_connection.save()

    def generate_s3_report(self, data={'account': {}}):
        # Avoid the use of the "root" account
        message_set ={
            'cis_1_20': "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
            "cis_2_1": 'Ensure all S3 buckets employ encryption-at-rest',
            "cis_2_2": 'Ensure S3 Bucket Policy allows HTTPS requests',
            "cis_2_3": 'Ensure EBS volume encryption is enabled',
        }
        remediation_set ={
            'cis_1_20': '''
            Remediation:

            If utilizing Block Public Access (bucket settings) From Console:
            1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
            2. Select the Check box next to the Bucket.
            3. Click on 'Edit public access settings'.
            4. Click 'Block all public access'
            5. Repeat for all the buckets in your AWS account that contain sensitive data.

            From Command Line:
            1. List all of the S3 Buckets
            aws s3 ls
            2. Set the public access to true on that bucket
            If utilizing Block Public Access (account settings)

            From Console:
            If the output reads true for the separate configuration settings then it is set on the account.
            1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
            2. Choose Block public access (account settings)
            3. Choose Edit to change the block public access settings for all the buckets in your
            AWS account
            4. Choose the settings you want to change, and then choose Save. For details about
            each setting, pause on the i icons.
            5. When you're asked for confirmation, enter confirm. Then Click Confirm to save your
            changes.
            ''',
            "cis_2_1": '''
            Remediation:

            From Console:
            1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
            2. Select the Check box next to the Bucket.
            3. Click on 'Properties'.
            4. Click on Default Encryption.
            5. Select either AES-256 or AWS-KMS
            6. Click Save
            7. Repeat for all the buckets in your AWS account lacking encryption.

            ''',
            "cis_2_2": '''
            Remediation: From Console:
            1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
            2. Select the Check box next to the Bucket.
            3. Click on 'Permissions'.
            4. Click 'Bucket Policy'
            5. Add this to the existing policy filling in the required information
            {
                "Sid": <optional>",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::<bucket_name>/*", "Condition": {
                        "Bool": {
                            "aws:SecureTransport": "false"
                } }
            }
            6. Save
            7. Repeat for all the buckets in your AWS account that contain sensitive data.
            ''',
            "cis_2_3": '''
            Remediation: From Console:
            1. Login to AWS Management Console and open the Amazon EC2 console using https://console.aws.amazon.com/ec2/
            2. Under Account attributes, click EBS encryption.
            3. Click Manage.
            4. Click the Enable checkbox.
            5. Click Update EBS encryption
            6. Repeat for every region requiring the change.
            Note: EBS volume encryption is configured per region.
            From Command Line:
            1. Run
            aws --region <region> ec2 enable-ebs-encryption-by-default.
            2. Verify that "EbsEncryptionByDefault": true is displayed.
            3. Repeat every region requiring the change.
            Note: EBS volume encryption is configured per region.
            '''
        }
        cis = AWSCISFramework()

        cis_keys = [
            'cis_1_20',
            'cis_2_1',
        ]
        for key in cis_keys:
            cis_n = cis.cis_n_check(data=data[key], n=key)
            self.create_aws_vuln(
                key=key,
                message_set=message_set,
                rule_set=None,
                policy=None,
                group="Storage",
                impacted_resources=data[key],
                active_or_fixed='fixed' if cis_n == None else 'active',
                remediation_set=remediation_set
            )
        return True

    def generate_logging_report(self, data={'account': {}}):
        cis = AWSCISFramework()
        cis_keys = [
            'cis_2_1',
            'cis_2_2',
            'cis_2_3',
            'cis_2_4',
            'cis_2_5',
            'cis_2_6',
            'cis_2_7',
            'cis_2_8',
        ]
        for key in cis_keys:
            cis_n = cis.cis_n_check(data=data[key]['Offenders'], n=key)
            message_set = {}
            remediation_set = {}
            message_set[key] = data[key]['Description']
            remediation_set[key] = data[key]['Remediation']
            self.create_aws_vuln(
                key=key,
                message_set=message_set,
                rule_set=None,
                policy=None,
                group="Logging",
                impacted_resources=data[key]['Offenders'],
                active_or_fixed='fixed' if cis_n == None else 'active',
                remediation_set=remediation_set
            )
        return True

    def generate_network_report(self, data={'account': {}}):
        cis = AWSCISFramework()
        cis_keys = [
            'cis_4_1',
            'cis_4_2',
            'cis_4_3',
            'cis_4_4',
            'cis_4_5',
        ]
        for key in cis_keys:
            cis_n = cis.cis_n_check(data=data[key]['Offenders'], n=key)
            message_set = {}
            remediation_set = {}
            message_set[key] = data[key]['Description']
            remediation_set[key] = data[key]['Remediation']
            self.create_aws_vuln(
                key=key,
                message_set=message_set,
                rule_set=None,
                policy=None,
                group="Network",
                impacted_resources=data[key]['Offenders'],
                active_or_fixed='fixed' if cis_n == None else 'active',
                remediation_set=remediation_set
            )
        return True

    def generate_monitoring_report(self, data={'account': {}}):
        cis = AWSCISFramework()
        cis_keys = [
            'cis_3_1',
            'cis_3_2',
            'cis_3_3',
            'cis_3_4',
            'cis_3_5',
            'cis_3_6',
            'cis_3_7',
            'cis_3_8',
            'cis_3_9',
            'cis_3_10',
            'cis_3_11',
            'cis_3_12',
            'cis_3_13',
            'cis_3_14',
            # 'cis_3_15',
        ]
        for key in cis_keys:
            cis_n = cis.cis_n_check(data=data[key]['Offenders'], n=key)
            message_set = {}
            remediation_set = {}
            message_set[key] = data[key]['Description']
            remediation_set[key] = data[key]['Remediation']
            self.create_aws_vuln(
                key=key,
                message_set=message_set,
                rule_set=None,
                policy=None,
                group="Monitoring",
                impacted_resources=data[key]['Offenders'],
                active_or_fixed='fixed' if cis_n == None else 'active',
                remediation_set=remediation_set
            )
        return True

    def generate_ec2_report(self, data={'account': {}}):
        # Avoid the use of the "root" account
        message_set ={
            "cis_2_3": 'Ensure EBS volume encryption is enabled',
        }
        remediation_set ={
            "cis_2_3": '''
            Remediation: From Console:
            1. Login to AWS Management Console and open the Amazon EC2 console using https://console.aws.amazon.com/ec2/
            2. Under Account attributes, click EBS encryption.
            3. Click Manage.
            4. Click the Enable checkbox.
            5. Click Update EBS encryption
            6. Repeat for every region requiring the change.
            Note: EBS volume encryption is configured per region.
            From Command Line:
            1. Run
            aws --region <region> ec2 enable-ebs-encryption-by-default.
            2. Verify that "EbsEncryptionByDefault": true is displayed.
            3. Repeat every region requiring the change.
            Note: EBS volume encryption is configured per region.
            '''
        }
        cis = AWSCISFramework()
        cis_keys = [
            'cis_2_3',
        ]
        for key in cis_keys:
            cis_n = cis.cis_n_check(data=data[key], n=key)
            self.create_aws_vuln(
                key=key,
                message_set=message_set,
                rule_set=None,
                policy=None,
                group="Storage / EBS",
                impacted_resources=data[key],
                active_or_fixed='fixed' if cis_n == None else 'active',
                remediation_set=remediation_set
            )
        return True

    def generate_iam_report(self, data={'account': {}}):
        # Avoid the use of the "root" account
        policy = data['account']
        rule_set ={
            # "AccessKeysPerUserQuota": 2,
            "AccountAccessKeysPresent": 0,
            "AccountMFAEnabled": 1,
            # "AccountSigningCertificatesPresent": 0,
            # "AssumeRolePolicySizeQuota": 2048,
            # "AttachedPoliciesPerGroupQuota": 10,
            # "AttachedPoliciesPerRoleQuota": 10,
            # "AttachedPoliciesPerUserQuota": 10,
            # "GlobalEndpointTokenVersion": 1,
            # "GroupPolicySizeQuota": 5120,
            # "Groups": 4,
            # "GroupsPerUserQuota": 10,
            # "GroupsQuota": 300,
            # "InstanceProfiles": 2,
            # "InstanceProfilesQuota": 1000,
            "MFADevices": 1,
            # "MFADevicesInUse": policy['Users'],
            # "Policies": 17,
            # "PoliciesQuota": 1500,
            # "PolicySizeQuota": 6144,
            # "PolicyVersionsInUse": 60,
            # "PolicyVersionsInUseQuota": 10000,
            # "Providers": 1,
            # "RolePolicySizeQuota": 10240,
            # "Roles": 45,
            # "RolesQuota": 1000,
            # "ServerCertificates": 0,
            # "ServerCertificatesQuota": 20,
            # "SigningCertificatesPerUserQuota": 2,
            # "UserPolicySizeQuota": 2048,
            # "Users": 6,
            # "UsersQuota": 5000,
            # "VersionsPerPolicyQuota": 5
        }
        message_set ={
            "AccountAccessKeysPresent": 'Ensure no root account access key exists',
            "AccountMFAEnabled": 'Ensure MFA is enabled for the "root" account',
            "MFADevices": 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password',
            "cis_1_7": 'Eliminate use of the root user for administrative and daily tasks',
            "cis_1_8": 'Ensure IAM password policy requires minimum length of 14 or greater',
            "cis_1_9": 'Ensure IAM password policy prevents password reuse',
            "cis_1_10": 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password',
            "cis_1_11": '''
            Do not setup access keys during initial user setup for all IAM users that have a console password
            ''',
            "cis_1_12": '''
            Ensure credentials unused for 90 days or greater are disabled
            ''',
            "cis_1_13": '''
            Ensure there is only one active access key available for any single IAM user
            ''',
            "cis_1_14": 'Ensure access keys are rotated every 90 days or less',
            "cis_1_15": 'Ensure IAM Users Receive Permissions Only Through Groups',
            "cis_1_16": 'Ensure IAM policies that allow full "*:*" administrative privileges are not attached',
            "cis_1_17": "Ensure a support role has been created to manage incidents with AWS Support",
            "cis_1_18": "Ensure IAM instance roles are used for AWS resource access from instances ",
            'cis_1_19': 'Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed',
            'cis_1_20': "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
            'cis_1_21': "Ensure that IAM Access analyzer is enabled",

            # "MFADevicesInUse": 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password'
        }
        remediation_set ={
            "AccountAccessKeysPresent": '''
            <strong>Remediation:</strong>
            Perform the following to delete or disable active root access keys being Via the AWS Console
            1. Sign in to the AWS Management Console as Root and open the IAM console at https://console.aws.amazon.com/iam/.
            2. Click on <Root_Account_Name> at the top right and select Security Credentials from the drop down list
            3. On the pop out screen Click on Continue to Security Credentials
            4. Click on Access Keys (Access Key ID and Secret Access Key)
            5. Under the Status column if there are any Keys which are Active
            1. Click on Make Inactive - (Temporarily disable Key - may be needed again)
            2. Click Delete - (Deleted keys cannot be recovered)
            ''',
            "AccountMFAEnabled": '''
            <strong>Remediation:</strong>
            Perform the following to establish a hardware MFA for the root account:
            1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            Note: to manage MFA devices for the root AWS account, you must use your root account credentials to sign in to AWS. You cannot manage MFA devices for the root account using other credentials.
            2. Choose Dashboard , and under Security Status , expand Activate MFA on your root account.
            3. Choose Activate MFA
            4. In the wizard, choose A hardware MFA device and then choose Next Step .
            5. In the Serial Number box, enter the serial number that is found on the back of the MFA device.
            6. In the Authentication Code 1 box, enter the six-digit number displayed by the MFA device. You might need to press the button on the front of the device to display the number.
            7. Wait 30 seconds while the device refreshes the code, and then enter the next six-digit number into the Authentication Code 2 box. You might need to press the button on the front of the device again to display the second number.
            8. Choose Next Step .
            The MFA device is now associated with the AWS account. The next time you use your AWS account credentials to sign in, you must type a code from the hardware MFA device.
            ''',
            "MFADevices": '''
            <strong>Remediation:</strong>
            Perform the following to enable MFA:
            1.Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            2.In the navigation pane, choose Users.
            3.In the User Name list, choose the name of the intended MFA user.
            4.Choose the Security Credentials tab, and then choose Manage MFA Device.
            5.In the Manage MFA Device wizard, choose A virtual MFA device, and then choose Next Step.IAM generates and displays configuration information for the virtual MFA device, including a QR code graphic. The graphic is a representation of the 'secret configuration key' that is available for manual entry on devices that do not support QR codes.
            6. Open your virtual MFA application. (For a list of apps that you can use for hosting virtual MFA devices, see Virtual MFA Applications.) If the virtual MFA application supports multiple accounts (multiple virtual MFA devices), choose the option to create a new account (a new virtual MFA device).
            7. Determine whether the MFA app supports QR codes, and then do one of the following:
            Use the app to scan the QR code. For example, you might choose the camera icon or choose an option similar to Scan code, and then use the device's camera to scan the code.
            In the Manage MFA Device wizard, choose Show secret key for manual configuration, and then type the secret configuration key into your MFA application.
            When you are finished, the virtual MFA device starts generating one-time passwords.
            8. In the Manage MFA Device wizard, in the Authentication Code 1 box, type the one-time password that currently appears in the virtual MFA device. Wait up to 30 seconds for the device to generate a new one-time password. Then type the second one-time password into the Authentication Code 2 box. Choose Active Virtual MFA.Forced IAM User Self-Service RemediationAmazon has published a pattern that forces users to self-service setup MFA before they have access to their complete permissions set. Until they complete this step, they cannot access their full permissions. This pattern can be used on new AWS accounts. It can also be used on existing accounts -it is recommended users are given instructions and a grace period to accomplish MFA enrollment before active enforcement on existing AWS accounts.How to Delegate Management of Multi-Factor Authentication to AWS IAM Users
            ''',
            "cis_1_7": '''
            <strong>Remediation:</strong>
            If you find that the root user account is being used for daily activity to include administrative tasks that do not require the root user:
            1. Change the root user password.
            2. Deactivate or delete any access keys associate with the root user.
            **Remember, anyone who has root user credentials for your AWS account has unrestricted access to and control of all the resources in your account, including billing information.
            ''',
            "cis_1_8": '''
            <strong>Remediation:</strong>
            Perform the following to set the password policy as prescribed:
            From Console:
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Set "Minimum password length" to 14 or greater.
            5. Click "Apply password policy"
            From Command Line:
            aws iam update-account-password-policy --minimum-password-length 14
            Note: All commands starting with "aws iam update-account-password-policy" can be combined into a single command.
            ''',
            "cis_1_9": '''
            <strong>Remediation:</strong>
            Perform the following to set the password policy as prescribed:
            From Console:
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Check "Prevent password reuse"
            5. Set "Number of passwords to remember" is set to 24

            From Command Line:
            aws iam update-account-password-policy --password-reuse-prevention 24

            Note: All commands starting with "aws iam update-account-password-policy" can be combined into a single command.
            ''',
            "cis_1_10": '''
            <strong>Remediation:</strong>
            Perform the following to enable MFA:
            From Console:
            1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            2. In the navigation pane, choose Users.
            3. In the User Name list, choose the name of the intended MFA user.
            4. Choose the Security Credentials tab, and then choose Manage MFA Device.
            5. In the Manage MFA Device wizard, choose Virtual MFA device, and then choose
            Continue.
            IAM generates and displays configuration information for the virtual MFA device, including a QR code graphic. The graphic is a representation of the 'secret configuration key' that is available for manual entry on devices that do not support QR codes.
            6. Open your virtual MFA application. (For a list of apps that you can use for hosting virtual MFA devices, see Virtual MFA Applications.) If the virtual MFA application supports multiple accounts (multiple virtual MFA devices), choose the option to create a new account (a new virtual MFA device).
            7. Determine whether the MFA app supports QR codes, and then do one of the following:
             Use the app to scan the QR code. For example, you might choose the camera icon or choose an option similar to Scan code, and then use the device's camera to scan the code.
             In the Manage MFA Device wizard, choose Show secret key for manual configuration, and then type the secret configuration key into your MFA application.
            When you are finished, the virtual MFA device starts generating one-time passwords.

            8. In the Manage MFA Device wizard, in the MFA Code 1 box, type the one-time password that currently appears in the virtual MFA device. Wait up to 30 seconds for the device to generate a new one-time password. Then type the second one-time password into the MFA Code 2 box. Choose Assign MFA.

            Forced IAM User Self-Service Remediation
            Amazon has published a pattern that forces users to self-service setup MFA before they have access to their complete permissions set. Until they complete this step, they cannot access their full permissions. This pattern can be used on new AWS accounts. It can also be used on existing accounts - it is recommended users are given instructions and a grace period to accomplish MFA enrollment before active enforcement on existing AWS accounts. How to Delegate Management of Multi-Factor Authentication to AWS IAM Users
            ''',
            "cis_1_11": '''
            <strong>Remediation:</strong>
            Perform the following to delete access keys that do not pass the audit:
            From Console:
            1. Login to the AWS Management Console:
            2. Click Services
            3. Click IAM
            4. Click on Users
            5. Click on Security Credentials
            6. As an Administrator
             Click on the X (Delete) for keys that were created at the same time as the user profile but have not been used.
            7. As an IAM User
             Click on the X (Delete) for keys that were created at the same time as the user profile but have not been used.
            ''',
            "cis_1_12": '''
            <strong>Remediation:</strong>
            From Console:
            Perform the following to manage Unused Password (IAM user console access)
            1. Login to the AWS Management Console:
            2. Click Services
            3. Click IAM
            4. Click on Users
            5. Click on Security Credentials
            6. Select user whose Console last sign-in is greater than 90 days
            7. Click Security credentials
            8. In section Sign-in credentials, Console paassword click Manage
            9. Under Console Access select Disable
            10.Click Apply
            Perform the following to deactivate Access Keys:
            1. Login to the AWS Management Console:
            2. Click Services
            3. Click IAM
            4. Click on Users
            5. Click on Security Credentials
            6. Select any access keys that are over 90 days old and that have been used and
             Click on Make Inactive
            7. Select any access keys that are over 90 days old and that have not been used and  Click the X to Delete
            ''',
            "cis_1_13": '''
            <strong>Remediation:</strong>
            From Console:
            1. Sign in to the AWS Management Console and navigate to IAM dashboard at https://console.aws.amazon.com/iam/.
            2. In the left navigation panel, choose Users.
            3. Click on the IAM user name that you want to examine.
            4. On the IAM user configuration page, select Security Credentials tab.
            5. In Access Keys section, choose one access key that is less than 90 days old. This
            should be the only active key used by this IAM user to access AWS resources programmatically. Test your application(s) to make sure that the chosen access key is working.
            6. In the same Access Keys section, identify your non-operational access keys (other than the chosen one) and deactivate it by clicking the Make Inactive link.
            7. If you receive the Change Key Status confirmation box, click Deactivate to switch off the selected key.
            8. Repeat steps no. 3 – 7 for each IAM user in your AWS account.
            From Command Line:
            1. Using the IAM user and access key information provided in the Audit CLI, choose one access key that is less than 90 days old. This should be the only active key used by this IAM user to access AWS resources programmatically. Test your application(s) to make sure that the chosen access key is working.
            2. Run the update-access-key command below using the IAM user name and the non- operational access key IDs to deactivate the unnecessary key(s). Refer to the Audit section to identify the unnecessary access key ID for the selected IAM user
            Note - the command does not return any output:
             43 | P a g e
              aws iam update-access-key --access-key-id <access-key-id> --status Inactive - -user-name <user-name>
             3. To confirm that the selected access key pair has been successfully deactivated run the list-access-keys audit command again for that IAM User:
            aws iam list-access-keys --user-name <user-name>
             The command output should expose the metadata for each access key associated with the IAM user. If the non-operational key pair(s) Status is set to Inactive, the key has been successfully deactivated and the IAM user access configuration adheres now to this recommendation.
            4. Repeat steps no. 1 – 3 for each IAM user in your AWS account.
            ''',
            "cis_1_14": '''
            <strong>Remediation:</strong>
            Perform the following to rotate access keys:
            From Console:
            1. Go to Management Console (https://console.aws.amazon.com/iam)
            2. Click on Users
            3. Click on Security Credentials
            4. As an Administrator
            o Click on Make Inactive for keys that have not been rotated in 90 Days 5. As an IAM User
            o Click on Make Inactive or Delete for keys which have not been rotated or used in 90 Days
            6. Click on `` Create Access Key
            7. Update programmatic call with new Access Key credentials
            From Command Line:
            1. While the first access key is still active, create a second access key, which is active by default. Run the following command:
            aws iam create-access-key
            At this point, the user has two active access keys.
            2. Update all applications and tools to use the new access key.
            3. Determine whether the first access key is still in use by using this command:
            aws iam get-access-key-last-used
            4. One approach is to wait several days and then check the old access key for any use before proceeding.
            Even if step Step 3 indicates no use of the old key, it is recommended that you do not immediately delete the first access key. Instead, change the state of the first access key to Inactive using this command:
            aws iam update-access-key
            5. Use only the new access key to confirm that your applications are working. Any applications and tools that still use the original access key will stop working at this point because they no longer have access to AWS resources. If you find such an application or tool, you can switch its state back to Active to reenable the first access key. Then return to step Step 2 and update this application to use the new key.
            6. After you wait some period of time to ensure that all applications and tools have been updated, you can delete the first access key with this command:
            aws iam delete-access-key
            ''',
            "cis_1_15": '''
            <strong>Remediation:</strong>

            Perform the following to create an IAM group and assign a policy to it:
            1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            2. In the navigation pane, click Groups and then click Create New Group .
            3. In the Group Name box, type the name of the group and then click Next Step .
            4. In the list of policies, select the check box for each policy that you want to apply to
            all members of the group. Then click Next Step .
            5. Click Create Group
            Perform the following to add a user to a given group:
            1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            2. In the navigation pane, click Groups
            3. Select the group to add a user to
            4. Click Add Users To Group
            5. Select the users to be added to the group
            6. Click Add Users
            Perform the following to remove a direct association between a user and policy:
            1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            2. In the left navigation pane, click on Users
            3. For each user:
             Select the user
             Click on the Permissions tab
             Expand Permissions policies
             Click X for each policy; then click Detach or Remove (depending on policy
            type)
            ''',
            "cis_1_16": '''
            <strong>Remediation:</strong>

            From Console:
            Perform the following to detach the policy that has full administrative privileges:
            1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
            2. In the navigation pane, click Policies and then search for the policy name found in the audit step.
            3. Select the policy that needs to be deleted.
            4. In the policy action menu, select first Detach
            5. Select all Users, Groups, Roles that have this policy attached
            6. Click Detach Policy
            7. In the policy action menu, select Detach
            From Command Line:
            Perform the following to detach the policy that has full administrative privileges as found in the audit step:
            1. Lists all IAM users, groups, and roles that the specified managed policy is attached to.
            aws iam list-entities-for-policy --policy-arn <policy_arn>
            2. Detach the policy from all IAM Users:
            aws iam detach-user-policy --user-name <iam_user> --policy-arn <policy_arn>
            3. Detach the policy from all IAM Groups:
            4. Detach the policy from all IAM Roles:
            aws iam detach-role-policy --role-name <iam_role> --policy-arn <policy_arn>
            ''',
            "cis_1_17": '''
            <strong>Remediation:</strong>
            From Command Line:
            1. Create an IAM role for managing incidents with AWS:
             Create a trust relationship policy document that allows <iam_user> to manage AWS incidents, and save it locally as /tmp/TrustPolicy.json:
            {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Principal": {
                    "AWS": "<iam_user>"
                  },
                  "Action": "sts:AssumeRole"
                }
            ] }
            2. Create the IAM role using the above trust policy:
            3. Attach 'AWSSupportAccess' managed policy to the created IAM role:
            References:
            1. https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs- inline.html
            2. https://aws.amazon.com/premiumsupport/pricing/
            3. https://docs.aws.amazon.com/cli/latest/reference/iam/list-policies.html
            4. https://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html
            5. https://docs.aws.amazon.com/cli/latest/reference/iam/list-entities-for-policy.html
              aws iam create-role --role-name <aws_support_iam_role> --assume-role-policy- document file:///tmp/TrustPolicy.json
              aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess --role-name <aws_support_iam_role>

            Additional Information:
            AWSSupportAccess policy is a global AWS resource. It has same ARN as arn:aws:iam::aws:policy/AWSSupportAccess for every account.
            ''',
            "cis_1_18": '''
            <strong>Remediation:</strong>

            IAM roles can only be associated at the launch of an instance. To remediate an instance to add it to a role you must create a new instance.
            If the instance has no external dependencies on its current private ip or public addresses are elastic IPs:
            1. In AWS IAM create a new role. Assign a permissions policy if needed permissions are already known.
            2. In the AWS console launch a new instance with identical settings to the existing instance, and ensure that the newly created role is selected.
            3. Shutdown both the existing instance and the new instance.
            4. Detach disks from both instances.
            5. Attach the existing instance disks to the new instance.
            6. Boot the new instance and you should have the same machine, but with the
            associated role.

            Note: if your environment has dependencies on a dynamically assigned PRIVATE IP address you can create an AMI from the existing instance, destroy the old one and then when launching from the AMI, manually assign the previous private IP address.
            Note: if your environment has dependencies on a dynamically assigned PUBLIC IP address there is not a way ensure the address is retained and assign an instance role. Dependencies on dynamically assigned public IP addresses are a bad practice and, if possible, you may wish to rebuild the instance with a new elastic IP address and make the investment to remediate affected systems while assigning the system to a role.

            ''',
            'cis_1_19': '''
            <strong>Remediation:</strong>
            From Console:
            Removing expired certificates via AWS Management Console is not currently supported. To delete SSL/TLS certificates stored in IAM via the AWS API use the Command Line Interface (CLI).
            From Command Line:
            To delete Expired Certificate run following command by replacing <CERTIFICATE_NAME> with the name of the certificate to delete:
             aws iam delete-server-certificate --server-certificate-name <CERTIFICATE_NAME>
            When the preceding command is successful, it does not return any output.

            Default Value:
            By default, expired certificates won't get deleted.
            ''',
            'cis_1_20': '''
            <strong>Remediation:</strong>

            If utilizing Block Public Access (bucket settings) From Console:
            1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
            2. Select the Check box next to the Bucket.
            3. Click on 'Edit public access settings'.
            4. Click 'Block all public access'
            5. Repeat for all the buckets in your AWS account that contain sensitive data.

            From Command Line:
            1. List all of the S3 Buckets
            aws s3 ls
            2. Set the public access to true on that bucket
            If utilizing Block Public Access (account settings)

            From Console:
            If the output reads true for the separate configuration settings then it is set on the account.
            1. Login to AWS Management Console and open the Amazon S3 console using https://console.aws.amazon.com/s3/
            2. Choose Block public access (account settings)
            3. Choose Edit to change the block public access settings for all the buckets in your
            AWS account
            4. Choose the settings you want to change, and then choose Save. For details about
            each setting, pause on the i icons.
            5. When you're asked for confirmation, enter confirm. Then Click Confirm to save your
            changes.
            ''',
            'cis_1_21': '''
            <strong>Remediation:</strong>

            From Console:
            Perform the following to enable IAM Access analyzer for IAM policies:
            1. Open the IAM console at https://console.aws.amazon.com/iam/.
            2. Choose Access analyzer.
            3. Choose Create analyzer.
            4. On the Create analyzer page, confirm that the Region displayed is the Region where
            you want to enable Access Analyzer.
            5. Enter a name for the analyzer.
            6. Optional. Add any tags that you want to apply to the analyzer.
            7. Choose Create Analyzer.

            From Command Line:
            Run the following command:
            aws accessanalyzer create-analyzer --analyzer-name --type
            Note: The IAM Access Analyzer is successfully configured only when the account you use has the necessary permissions.
            '''
        }
        cis = AWSCISFramework()
        for key in rule_set.keys():
            active_or_fixed = 'fixed' if rule_set[key] == policy[key] else 'active'
            self.create_aws_vuln(
                key=key,
                message_set=message_set,
                rule_set=rule_set,
                policy=policy,
                active_or_fixed=active_or_fixed,
                remediation_set=remediation_set
            )
        cis_1_7 = cis.cis_1_7_check(data['cred_report'])
        self.create_aws_vuln(
            key='cis_1_7',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            active_or_fixed='fixed' if cis_1_7 == None else 'active',
            remediation_set=remediation_set
        )
        cis_1_8 = cis.cis_1_8_check(data['password_policy'])
        self.create_aws_vuln(
            key='cis_1_8',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            active_or_fixed='fixed' if cis_1_8 == None else 'active',
            remediation_set=remediation_set
        )
        cis_1_9 = cis.cis_1_9_check(data['password_policy'])
        self.create_aws_vuln(
            key='cis_1_9',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            active_or_fixed='fixed' if cis_1_9 == None else 'active',
            remediation_set=remediation_set
        )
        cis_1_10 = cis.cis_1_10_check(data['cred_report'])
        self.create_aws_vuln(
            key='cis_1_10',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            active_or_fixed='fixed' if cis_1_10 == None else 'active',
            remediation_set=remediation_set
        )
        cis_1_11 = cis.cis_1_11_check(data['cred_report'])
        self.create_aws_vuln(
            key='cis_1_11',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            active_or_fixed='fixed' if cis_1_11 == None else 'active',
            remediation_set=remediation_set
        )
        cis_1_12 = cis.cis_1_12_check(data['cred_report'])
        self.create_aws_vuln(
            key='cis_1_12',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            active_or_fixed='fixed' if cis_1_12 == None else 'active',
            remediation_set=remediation_set
        )
        cis_1_13 = cis.cis_1_13_check(data['cred_report'])
        self.create_aws_vuln(
            key='cis_1_13',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            active_or_fixed='fixed' if cis_1_13 == None else 'active',
            remediation_set=remediation_set
        )
        cis_1_14 = cis.cis_1_14_check(data['cred_report'])
        self.create_aws_vuln(
            key='cis_1_14',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            active_or_fixed='fixed' if cis_1_14 == None else 'active',
            remediation_set=remediation_set
        )
        # cis_1_15 = cis.cis_1_15_check(data['cis_1_15'])
        # self.create_aws_vuln(
        #     key='cis_1_15',
        #     message_set=message_set,
        #     rule_set=rule_set,
        #     policy=policy,
        #     active_or_fixed='fixed' if cis_1_15 == None else 'active',
        #     remediation_set=remediation_set
        # )
        cis_keys = [
            'cis_1_15',
            'cis_1_16',
            'cis_1_17',
            'cis_1_18',
            'cis_1_19',
            # 'cis_1_20',
            # 'cis_1_22',
        ]
        for key in cis_keys:
            cis_n = cis.cis_n_check(data=data[key], n=key)
            self.create_aws_vuln(
                key=key,
                message_set=message_set,
                rule_set=rule_set,
                policy=policy,
                impacted_resources=data[key],
                active_or_fixed='fixed' if cis_n == None else 'active',
                remediation_set=remediation_set
            )
        cis_1_21 = cis.cis_1_21_check(data['list_analyzers'])
        self.create_aws_vuln(
            key='cis_1_21',
            message_set=message_set,
            rule_set=rule_set,
            policy=policy,
            impacted_resources=data['list_analyzers'],
            active_or_fixed='fixed' if cis_1_21 == None else 'active',
            remediation_set=remediation_set
        )

        return policy
        # Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password
        # return True

    def create_aws_vuln(
        self, key, message_set,
        remediation_set,
        active_or_fixed,
        rule_set=None, policy=None,
        impacted_resources=None,
        group='IAM / Security'
        ):
        finding, created = self.finding_set.get_or_create(
            source_type='bpr',
            severity=3,
            title=message_set[key],
            name=message_set[key],
            bpr=self,
        )
        # print(finding.id, created)
        finding.company = self.company
        finding.qualys = self.company.qualys
        if created == True:
            if active_or_fixed == 'fixed':
                finding.status = 'FIXED'
            else:
                finding.status = 'NEW'
            finding.first_detected_date = now()
        else:
            if finding.status in ['ACTIVE', 'NEW']:
                finding.status = 'ACTIVE'
            else:
                finding.status = 'REOPENED'
        if active_or_fixed == 'fixed':
            finding.status = 'FIXED'
        finding.finding_type = "Cloud BPA"
        finding.group = group
        finding.solution = remediation_set[key].replace('\n','</br>')
        finding.impact = 'All IAM Users'
        finding.active_or_fixed = active_or_fixed
        finding.last_tested_date = now()
        finding.last_detected_date = now()
        finding.title = message_set[key]
        finding.name = message_set[key]
        finding.published_datetime = now()
        finding.last_processed_datetime = now()
        finding.last_service_modification_datetime = now()
        if impacted_resources is not None:
            finding.result_list = json.dumps(impacted_resources)
        finding.save()

    def generate_password_report(self, data={'password_policy': {}}):
        # data = self.get_realtime_data(return_type='i-decrypt')
        password_policy = data['password_policy']
        rule_set ={
            "AllowUsersToChangePassword": False,
            "ExpirePasswords": False,
            "MinimumPasswordLength": 14,
            "RequireLowercaseCharacters": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
            "RequireUppercaseCharacters": True
        }
        message_set ={
            "AllowUsersToChangePassword": 'Ensure Users are allowed to rotate their password',
            "ExpirePasswords": 'Ensure IAM password policy expires passwords within 90 days or less',
            "MinimumPasswordLength": 'Ensure IAM password policy requires minimum length of 14 or greater',
            "RequireLowercaseCharacters": 'Ensure IAM password policy require at least one lowercase letter',
            "RequireNumbers": 'Ensure IAM password policy require at least one number',
            "RequireSymbols": 'Ensure IAM password policy require at least one symbol',
            "RequireUppercaseCharacters": 'Ensure IAM password policy require at least one uppercase letter'
        }
        remediation_set ={
            "AllowUsersToChangePassword": '''
            <strong>Remediation</strong>
            Perform the following to set the password policy as prescribed: Via AWS Console
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Check "Requires at least one uppercase letter"
            5. Click "Apply password policy"''',
            "ExpirePasswords": '''
            <strong>Remediation</strong>
            Perform the following to set the password policy as prescribed: Via AWS Console:
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Check "Enable password expiration"
            5. Set "Password expiration period (in days):" to 90 or less
            ''',
            "MinimumPasswordLength": '''
            <strong>Remediation</strong>
            Perform the following to set the password policy as prescribed: Via AWS Console
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Set "Minimum password length" to 14 or greater.
            5. Click "Apply password policy"
            ''',
            "RequireLowercaseCharacters": '''
            <strong>Remediation</strong>
            Perform the following to set the password policy as prescribed: Via the AWS Console
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Check "Requires at least one lowercase letter"
            5. Click "Apply password policy"
            ''',
            "RequireNumbers": '''
            <strong>Remediation</strong>
            Perform the following to set the password policy as prescribed: Via AWS Console
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Check "Require at least one number"
            5. Click "Apply password policy"
            ''',
            "RequireSymbols": '''
            <strong>Remediation</strong>
            Perform the following to set the password policy as prescribed: Via AWS Console
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Check "Require at least one non-alphanumeric character"
            5. Click "Apply password policy"
            ''',
            "RequireUppercaseCharacters": '''
            <strong>Remediation</strong>
            Perform the following to set the password policy as prescribed: Via AWS Console
            1. Login to AWS Console (with appropriate permissions to View Identity Access Management Account Settings)
            2. Go to IAM Service on the AWS Console
            3. Click on Account Settings on the Left Pane
            4. Check "Requires at least one uppercase letter"
            5. Click "Apply password policy"
            '''
        }
        for key in password_policy.keys():
            active_or_fixed = 'active' if rule_set[key] == password_policy[key] else 'fixed'
            finding, created = self.finding_set.get_or_create(
                source_type='bpr',
                severity=3,
                title=message_set[key],
                name=message_set[key],
                bpr=self,
            )
            # print(finding.id, created)
            finding.company = self.company
            finding.qualys = self.company.qualys
            if created == True:
                finding.status = 'NEW'
                finding.first_detected_date = now()
            else:
                if finding.status in ['ACTIVE', 'NEW']:
                    finding.status = 'ACTIVE'
                else:
                    finding.status = 'REOPENED'
            finding.finding_type = "Cloud BPA"
            finding.group = 'IAM / Security'
            finding.solution = remediation_set[key]
            finding.impact = 'All IAM Users'
            finding.active_or_fixed = active_or_fixed
            finding.last_tested_date = now()
            finding.last_detected_date = now()
            finding.title = message_set[key]
            finding.name = message_set[key]
            finding.published_datetime = now()
            finding.last_processed_datetime = now()
            finding.last_service_modification_datetime = now()
            finding.save()
        return password_policy

    def add_secret_token(self, token):
        encrypted_data = bprencrypt(token)
        text = encrypted_data['ciphertext']
        tag = encrypted_data['tag']
        url = settings.ABP_FRAMEWORK_URL+'/secrets/'#.format(qualys.api_url)
        headers = ABP_HEADER
        payload = {
            'text': text,
            'key': tag,
            'uuid': self.uuid
        }
        response = request("POST", url, headers=headers, data=json.dumps(payload))
        # if response.status_code != 200:
        #     self.deactivate()
        return True
