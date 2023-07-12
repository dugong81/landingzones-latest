# Reference:
#   https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm#seven__Python
#   https://www.ateam-oracle.com/post/oracle-cloud-infrastructure-oci-rest-call-walkthrough-with-curl

import argparse
import oci
import os
import json
import requests


class ManageIdentityDomain:
    def __init__(self, action, domain_id, group_names):
        self.config, self.auth = self.set_up_oci_config()
        self.identity_client = oci.identity.IdentityClient(self.config)

        self.action = action
        self.host = self.get_domain_url(domain_id)
        self.group_endpoint = self.host + "/admin/v1/Groups"
        self.group_names = group_names

    def set_up_oci_config(self):
        '''
        check terraform environment variables, prefixed by TF_, so it can run in our pipeline
        '''
        try:
            profile_name = "DEFAULT" if os.environ.get(
                "PROFILE_NAME") == None else os.environ.get("PROFILE_NAME")
            config = oci.config.from_file(profile_name=profile_name)
            auth = oci.Signer(
                tenancy=config['tenancy'],
                user=config['user'],
                fingerprint=config['fingerprint'],
                private_key_file_location=config['key_file']
            )
        except oci.exceptions.ConfigFileNotFound:

            '''
            tenancy = os.environ.get("TF_VAR_tenancy_ocid")
            user = os.environ.get("TF_VAR_current_user_ocid")
            fingerprint = os.environ.get("TF_VAR_api_fingerprint")
            private_key_file = os.environ.get("TF_VAR_api_private_key")
            region = os.environ.get("TF_VAR_region")

            config = {
                "user": user,
                "key_content": private_key_file,
                "fingerprint": fingerprint,
                "tenancy": tenancy,
                "region": region,
            }
            auth = oci.Signer(
                tenancy=config['tenancy'],
                user=config['user'],
                fingerprint=config['fingerprint'],
                private_key_content=config["key_content"],
                private_key_file_location=None
            )
            '''
            config = {}
            obo_token = os.environ.get("OCI_obo_token")
            auth = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
                delegation_token=obo_token)
        return config, auth

    def get_domain_url(self, domain_id):
        print("Waiting for domain to enter ACTIVE state")
        get_domain_response = self.identity_client.get_domain(
            domain_id=domain_id)
        wait_until_domain_available_response = oci.wait_until(
            self.identity_client, get_domain_response, 'lifecycle_state', 'ACTIVE')

        print(
            f"Got domain url {wait_until_domain_available_response.data.url}")

        return wait_until_domain_available_response.data.url

    def create_group(self, group_name):
        body = {
            "displayName": group_name,
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:Group",
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:group:Group"
            ]
        }

        response = requests.post(
            self.group_endpoint, json=body, auth=self.auth)
        response.raise_for_status()

        print(
            f"Display Name: {group_name} \tOCID: {json.loads(response.content)['ocid']}")

    def get_group(self, group_name):
        response = requests.get(
            self.group_endpoint + "?filter=displayName+eq+%22"+group_name+"%22", auth=self.auth)
        response.raise_for_status()
        return json.loads(response.content)['Resources'][0]

    def create_groups(self):
        for group in self.group_names:
            print(f"Provisioning group {group}")
            try:
                self.create_group(group)
            except requests.HTTPError as e:
                print(f"Error creating group {group}")
                print(e)

    def delete_group(self, group_name):
        response = requests.delete(
            self.group_endpoint + f"/" + self.get_group(group_name)['ocid'], auth=self.auth)
        response.raise_for_status()

        print(f"Deleted Group: \t{group_name}")

    def delete_groups(self):
        for group in self.group_names:
            print(f"Deleting group {group}")
            try:
                self.delete_group(group)
            except requests.HTTPError as e:
                print(f"Error deleting group {group}")
                print(e)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Manage an Identity Domain")
    parser.add_argument('-a', '--action',
                        help="<Required> Create or Delete",
                        required=True)
    parser.add_argument('-d', '--domain_id',
                        help="<Required> Id of the domain to manage",
                        required=True)
    parser.add_argument('-g', '--group_names',
                        nargs='+',
                        help='<Required> Names of the groups to create (space seperated)',
                        required=True)

    args = parser.parse_args()
    manage_id = ManageIdentityDomain(
        args.action, args.domain_id, args.group_names)
    if (manage_id.action == "create"):
        manage_id.create_groups()
    if (manage_id.action == "delete"):
        manage_id.delete_groups()
