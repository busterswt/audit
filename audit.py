#!/usr/bin/env python

import json
import getpass
from ltm import LTM
import argparse


#ip = raw_input("MGMT IP: ")
#username = raw_input("Tacacs Username: ")
#password = getpass.getpass("Tacacs Password: ")
#
#url = 'https://%s' % ip
#payload = { "password": password }
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

def remidiate_device(audit):
    print 'Remidiating!'
    if audit.has_key('vlans'):
        print 'Checking VLANs...'
        check_vlans(audit['vlans'])

def check_vlans(vlans):
    # Check VLANs to ensure failsafe is set
    for vlan in vlans:
        string1 = 'RPC_'
        string2 = vlan['name']

        if string1.lower() in string2.lower():
        # Check for failsafe
            failsafe = vlan['failsafe']
            failsafeAction = vlan['failsafeAction']

            if 'enable' not in failsafe:
                print "tmsh modify net vlan %s failsafe enabled failsafe-action failover" % (vlan['fullPath'])



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', help='F5 hostname or IP', required=True)
    parser.add_argument('--username', help='TACACS or local username', required=True)
    parser.add_argument('-r','--remediate', help='Provide guidance on changes',type=bool)
    args = vars(parser.parse_args())

    # Prompt the user for their password
    # Prompt the user for their password
    password = getpass.getpass("Password: ")

    ltm = LTM(hostname=args['host'], username=args['username'], password=password, partition='RPC')

    audit = json.dumps(audit_device(ltm))

    if args.has_key('remidiate'):
        if args['remidiate']:
            print remidiate_device(audit)
    else:
        print audit