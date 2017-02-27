#!/usr/bin/env python

import requests
import json
import getpass
import sys
import prettytable
from ltm import LTM
from prettytable import PrettyTable

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
            string1 = 'GALERA'
            string2 = vs['name']
            if string1.lower() in string2.lower():
                virtdetails = { "name": vs['name'], "pool": vs['pool'], "mirroring": vs['mirror'] }
                details['virtuals'].append(virtdetails)

    # 3. Return VLAN details (look for failsafe)
    details['vlans'] = []
    vlanlist = ltm.get_vlans()

    # Check to see if any vlans are returned
    if vlanlist.has_key('items'):
       	for vlan in vlanlist['items']:
            string1 = 'RPC_'
            string2 = vlan['name']
            if string1.lower() in string2.lower():
                vlandetails = { "name": vlan['name'], "tag": vlan['tag'], "failsafe": vlan['failsafe'], "failsafeAction": vlan['failsafeAction'] }
                details['vlans'].append(vlandetails)

    # Return!
    return details

if __name__ == "__main__":
    ltm = LTM(hostname=ip, username=username, password=password, partition='RPC')

    print json.dumps(audit_device(ltm))