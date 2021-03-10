# Use 'python3 ipgather.py domain.com'
import shodan

import requests
import sys
import time
import socket

__Author__ = 'joignacio'
def banner():
    banner = '''
  _____ _____   _____       _______ _    _ ______ _____  
 |_   _|  __ \ / ____|   /\|__   __| |  | |  ____|  __ \ 
   | | | |__) | |  __   /  \  | |  | |__| | |__  | |__) |
   | | |  ___/| | |_ | / /\ \ | |  |  __  |  __| |  _  / 
  _| |_| |    | |__| |/ ____ \| |  | |  | | |____| | \ \ 
 |_____|_|     \_____/_/    \_\_|  |_|  |_|______|_|  \_\


                hollistic server lookup
                    author: joignacio
	'''
    print(banner)

domain=str(sys.argv[1])
#comment the line above if you want to set the domain value for quicker testing
#domain=""
banner()
SHODAN_API_KEY = "" #set your shodan api key here
apikey="" #set your whoisxmlapi.com api key here
api = shodan.Shodan(SHODAN_API_KEY)
ssldic=[]

iplist=[]
hostlist=[]
response = requests.get("https://subdomains.whoisxmlapi.com/api/v1?apiKey=" + apikey + "&domainName=" + domain)
if response.status_code == 200:
    data = response.json()
    result = data['result']
    count = result['count']
    records = result['records']
    for i in range(count):
        sub = records[i]
        sub = sub['domain']
        hostlist.append(sub)
if response.status_code != 200:
    print("Error!")
if response.status_code == 403:
    print("Check balance!")
print("[*] Subdomains found ("+str(len(hostlist))+"): ")
for z in range(len(hostlist)):
    print(hostlist[z])
print("----------------------------------------")
for x in range(len(hostlist)):
    try:
        dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + hostlist[x] + '&key=' + SHODAN_API_KEY
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[hostlist[x]]
        iplist.append(hostIP)
        time.sleep(1) # prevent dropped requests from shodan, min. 1s
    except:
        print("EXCEPT RESOLVING")
iplist=list(dict.fromkeys(iplist))
ipq=len(iplist)
print("[*] Initial IPS:")
for u in range(len(iplist)):
    print(iplist[u])
print("----------------------------------------")
for n in range(ipq):
    try:
        host = api.host(iplist[n])
        for item in host['data']:
            try:
                sslowner = item['ssl']
                sslowner = sslowner['cert']
                sslowner = sslowner['subject']
                sslowner = sslowner['O']
                print("[*] Gathed SSL: %s" % sslowner)
                ssldic.append(sslowner)
            except:
                False
        time.sleep(1)
        try:
            reverse = api.search('ssl:"' + ssldic[0] + '"')
            for k in range(len(ssldic)):
                for item in reverse['matches']:
                    iplist.append(item['ip_str'])
        except:
            print("No SSL gathed IPS")
    except:
        print("Unable to Gathe Info")
iplist=list(dict.fromkeys(iplist))
print("----------------------------------------")
print("[*] Gathed IPS:")
for u in range(len(iplist)):
    print(iplist[u])
print("----------------------------------------")
print("[*] Gathed Info:")
for u in range(len(iplist)):
    try:
        host = api.host(iplist[u])
        print("Ports:", end=" ")
        for item in host['data']:
            print(str(item['port']), end=" ")
        try:
            print("\nIP: %s" % host['ip_str'])
            print("Organization: %s" % host.get('org', 'n/a'))
            print("Operating System: %s" % host.get('os', 'n/a'))
            for item in host['vulns']:
                CVE = item.replace('!', '')
                print('Vuln: %s' % item)
                exploits = api.exploits.search(CVE)
                time.sleep(1)
            time.sleep(1)
        except:
            False
        print("----------------------------------------")
    except:
        print("No Info Available")