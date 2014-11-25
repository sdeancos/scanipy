#!/usr/bin/python
import socket
import sys
 
class Netstat(object):
 
    def __init__ (self):
        with open("/proc/net/tcp",'r') as f:
            self.content = f.readlines()
            self.content.pop(0)
 
    def _whois(self, address):
        try:
            data = socket.gethostbyaddr(address[0])[0]
        except Exception, ex:
            data = ex
 
        return data
 
    def _get_address(self):
        result = []
        sys.stdout.write( '\r' + ( '#' * 0 ) + ' get address')
        sys.stdout.flush()
        for line in self.content:
            line_array = [x for x in line.split(' ') if x !='']
            if line_array[2] != '00000000:0000':
                host,port = line_array[2].split(':')
                r_host = '.'.join([(str(int(host[6:8],16))),
                                   (str(int(host[4:6],16))),
                                   (str(int(host[2:4],16))),
                                   (str(int(host[0:2],16)))])
                result.append(r_host)
 
        return result
 
    def execute(self, interactive=False):
        self.final = []
        list_address = set(self._get_address())
        if interactive:
            self.interactive(list_address)
        else:
            self.non_interactive(list_address)
 
    def non_interactive(self, list_address):
        final = []
        count = 0
        for address in list_address:
            count = count + 1
            sys.stdout.write( '\r' + ( '#' * count ) + ' Scan Address:'\
             + address)
            final.append((self._whois(address), address))
            sys.stdout.flush()
 
        return final
 
    def interactive(self, list_address):
        for address in list_address:
            print address, self._whois(address)

if __name__ == '__main__':
    nestat = Netstat()
    nestat.execute(interactive=False)#Non interactive mode
    nestat.execute(interactive=True)#Interactive mode
