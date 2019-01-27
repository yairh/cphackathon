from ipwhois import IPWhois
import pprint

obj = IPWhois('74.125.227.206')
# obj = IPWhois('192.168.20.20')

results = obj.lookup_whois()

pprint.pprint(results)

results = obj.lookup_rdap()

# pprint.pprint(results)