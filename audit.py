#!/usr/bin/env python

import requests
import json
import getpass
import sys
from ltm import LTM

ip = raw_input("MGMT IP: ")
username = raw_input("Tacacs Username: ")
password = getpass.getpass("Tacacs Password: ")

url = 'https://%s' % ip
payload = { "password": password }
headers = { "User-Agent": "Mozilla/5.0 (RPC-N Audit)" }


# Things to do
# 0 Check for peer device??
# 1 Check for mirror setup (report back)
# 2 Check galera VIP for mirroring (report back)
# 3 Check for VLAN failsafe on VLANs (report back)

def audit_device(ltm):

    details = {}

    # 1. Connect to the BIGIP and return known devices
    details['devices'] = []
    devices = ltm.get_devices()

    # Test to see if there are any devices (should be). If so, list them.
    if devices.has_key('items'):
        for device in devices['items']:
            # Check for the existence of particular keys
            if not device.has_key('mirror-ip'):
                device['mirror-ip'] = "None"

            devdetails = { "hostname": device['hostname'], "model": device['marketingName'],
                           "version": device['version'], "hostfix": device['edition'],
                           "management_ip": device['managementIp'], "mirror_ip": device['mirror-ip'] }
            details['devices'].append(devdetails)

    # 2. Return Galera VIP config (look for mirroring)
    details['virtuals'] = []
    vslist = ltm.get_virtuals()

    # Check to see if any virtual servers are returned
    if vslist.has_key('items'):
        for vs in vslist['items']:
            if vs.has_key('pool'):
                pool = ltm.get_pool(vs['pool'].rsplit('/', 1)[-1])
            else:
                vs['pool'] = 'N/A'
                pool = { "loadBalancingMode": "N/A" }

            virtdetails = { "name": vs['name'], "pool": vs['pool'], "loadBalancingMode": pool['loadBalancingMode'], "mirroring": vs['mirror'] }
            details['virtuals'].append(virtdetails)

    # 3. Return VLAN details (look for failsafe)
    details['vlans'] = []
    vlanlist = ltm.get_vlans()
    selflist = ltm.get_selfips()

    # Check to see if any vlans are returned
    if vlanlist.has_key('items'):
        for vlan in vlanlist['items']:

            # Find the respective self ip for each vlan
            addresses = []
            for selfip in selflist['items']:
                if vlan['fullPath'] in selfip['vlan']:
                    addrdetails = { "address": selfip['address'], "floating": selfip['floating'], "fullPath": selfip['fullPath'] }
                    addresses.append(addrdetails)

            vlandetails = { "name": vlan['name'], "fullPath": vlan['fullPath'], "tag": vlan['tag'],
                            "failsafe": vlan['failsafe'], "failsafeAction": vlan['failsafeAction'],
                            "addresses": addresses }
            details['vlans'].append(vlandetails)

    # Return!
    return details

if __name__ == "__main__":
    ltm = LTM(hostname=ip, username=username, password=password, partition='RPC')

    print json.dumps(audit_device(ltm))
