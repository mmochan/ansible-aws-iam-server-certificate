# (c) 2016, Mike Mochan <@mmochan>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
DOCUMENTATION = '''
module: iam_server_cert
short_description: create, delete, list, get IAM server certificates.
description:
  - Read the AWS documentation for Managing IAM Server Certificates
    U(http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs_manage.html)
version_added: "2.1"
options:
  subject:
    description:
      - X509 subject details.
    required: true
  hostname:
    description:
      - The hostname of the server certificate.
    required: true
  state:
    description:
      - Creates a new IAM CERT
      - Deletes an IAM CERT
      - Lists all IAM Certs
      - Get a named cert
    required: false
    choices: ['present', 'absent', 'list', 'get']
    default: present
author: Mike Mochan(@mmochan)
extends_documentation_fragment: aws
'''

EXAMPLES = '''
- name: IAM Server Certificates
  hosts: localhost
  connection: local
  gather_facts: false

  tasks:
  - name: List Server certificates
    iam_server_cert:
      region: ap-southeast-2
      state: list
    register: list_certs

  - debug: msg="{{list_certs}}"

  - name: Create new server certificate
    iam_server_cert:
      region: ap-southeast-2
      subject:
        country: AU
        state: QLD
        location: Brisbane
        organization: Foo & Bar
        organization_unit: Cloud Team
      hostname: nginx01
      state: present
    register: certs

  - debug: msg="{{certs}}"

  - name: Get Server certificate
    iam_server_cert:
      region: ap-southeast-2
      hostname: nginx01
      state: get
    register: cert

  - debug: msg="{{cert}}"

  - name: Delete existing server certificate
    iam_server_cert:
      region: ap-southeast-2
      hostname: nginx01
      state: absent
    register: cert

  - debug: msg="{{cert}}"
'''
RETURN = '''
task:
  description: The result of the create, delete, list, or get action.
  returned: success
  type: dictionary
'''
try:
    import json
    import botocore
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from OpenSSL import crypto
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False


def create_server_certificate(client, module):
    subject = module.params.get('subject')
    hostname = module.params.get('hostname')

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = subject['country']
    cert.get_subject().ST = subject['state']
    cert.get_subject().L = subject['location']
    cert.get_subject().O = subject['organization']
    cert.get_subject().OU = subject['organization_unit']
    cert.get_subject().CN = hostname
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha1')

    server_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    server_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)

    try:
        resp = client.upload_server_certificate(
            Path='/', ServerCertificateName=hostname,
            CertificateBody=server_cert, PrivateKey=server_key)
        resp['ServerCertificateMetadata'].pop('Expiration')
        resp['ServerCertificateMetadata'].pop('UploadDate')
        resp.pop('ResponseMetadata')
        return True, resp
    except botocore.exceptions.ClientError as e:
        if "EntityAlreadyExists" in str(e):
            return get_server_certificate(client, module)
            #return False, "Skipping - already exists"
        else:
            module.fail_json(msg=str(e))


def list_server_certificates(client, module):
    try:
        resp = client.list_server_certificates()
        for cert in resp['ServerCertificateMetadataList']:
            cert.pop('Expiration')
            cert.pop('UploadDate')
        return False, resp['ServerCertificateMetadataList']
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=str(e))


def delete_server_certificate(client, module):
    try:
        resp = client.delete_server_certificate(
            ServerCertificateName=module.params.get('hostname'))
        return True, resp['ResponseMetadata']['HTTPStatusCode']
    except botocore.exceptions.ClientError as e:
        if "DeleteConflict" in str(e):
            return False, "Skipping - Certificate is in use"
        else:
            module.fail_json(msg=str(e))


def get_server_certificate(client, module):
    hostname = module.params.get('hostname')
    try:
        resp = client.get_server_certificate(ServerCertificateName=hostname)
        resp['ServerCertificate']['ServerCertificateMetadata'].pop('Expiration')
        resp['ServerCertificate']['ServerCertificateMetadata'].pop('UploadDate')
        resp.pop('ResponseMetadata')
        return False, resp
    except botocore.exceptions.ClientError as e:
        if "NoSuchEntity" in str(e):
            return False, "Skipping - That cert does not exist"
        else:
            module.fail_json(msg=str(e))


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        hostname=dict(required=False),
        subject=dict(required=False, type='dict', default=dict()),
        state=dict(default='present',
            choices=['present', 'absent', 'list', 'get']),
        ),
    )
    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_OPENSSL:
        module.fail_json(msg='pyopenssl is required.')

    if not HAS_BOTO3:
        module.fail_json(msg='json and boto3 is required.')
    state = module.params.get('state').lower()
    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        client = boto3_conn(module, conn_type='client', resource='iam', region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except botocore.exceptions.NoCredentialsError, e:
        module.fail_json(msg="Can't authorize connection - "+str(e))
    
    invocations = {
        "present": create_server_certificate,
        "absent": delete_server_certificate,
        "get": get_server_certificate,
        "list": list_server_certificates
    }

    (changed, results) = invocations[state](client, module)
    module.exit_json(changed=changed, certs=results)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
