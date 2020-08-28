#!/usr/bin/python
"""scanip.py Scan TCP connections (netstat/whois)

Usage:
  scanip.py [--interactive|--json]

Options:
  -h --help         Show this screen.
  --interactive     Interactive mode.
  --json            Show in json format.
"""
import socket
import json
try
    import docopt
except Exception as ex:
    print('Install docopt: pip install docopt')


class Netstat(object):
 
    def __init__(self):
        with open('/proc/net/tcp', 'r') as f:
            self.content = f.readlines()
            self.content.pop(0)
 
    def _whois(self, address):
        try:
            data = socket.gethostbyaddr(address[0])[0]
        except Exception as ex:
            data = ex
 
        return data
 
    def _get_address(self):
        result = []
        for line in self.content:
            line_array = [x for x in line.split(' ') if x != '']
            if line_array[2] != '00000000:0000':
                host, port = line_array[2].split(':')
                r_host = '.'.join([(str(int(host[6:8],16))),
                                   (str(int(host[4:6],16))),
                                   (str(int(host[2:4],16))),
                                   (str(int(host[0:2],16)))])
                result.append(r_host)
 
        return result
 
    def execute(self, interactive=False, json_arg=False):
        list_address = set(self._get_address())
        if interactive:
            result = self.interactive(list_address)
        else:
            result = self.non_interactive(list_address)
    
        if not interactive and json_arg:
            return json.dumps(result)
        else:
            return result
 
    def non_interactive(self, list_address):
        final = []
        for address in list_address:
            __whois = self._whois(address)
            final.append({address: __whois if not isinstance(__whois, socket.herror) else 'Unknown host'})

        return final

    def interactive(self, list_address):
        for address in list_address:
            __whois = self._whois(address)
            print('  {} -> {}'.format(address, __whois if not isinstance(__whois, socket.herror) else 'Unknown host'))

        return False

if __name__ == '__main__':
    arguments = docopt.docopt(__doc__)

    nestat = Netstat()
    result = nestat.execute(interactive=arguments.get('--interactive'), json_arg=arguments.get('--json'))

    if isinstance(result, str):
        print(result)
    elif isinstance(result, list):
        for i in result:
            for k, v in i.items():
                print('  {} -> {}'.format(k, v))
