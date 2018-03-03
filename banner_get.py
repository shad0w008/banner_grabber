#coding=utf-8

import socket,re,os,time,sys

#A simple banner grabber which connects to an open TCP port and prints out anything sent by the listening service within five seconds. referred to nmap script:banner.nse

REQUEST_TIMEOUT=3
filename=os.path.realpath(sys.path[0])+'\\results\\'+str(int(time.time()))+'-banner.txt'

banners={'13':'daytime','17':'qotd','21':'ftp','22':'ssh','23':'telnet','25':'smtp','53':'dns','110':'pop3','194':'irc','587':'submission','873':'rsync','992':'telnets','994':'ircs','6667':'ircd','5432':'postgres','465':'smtps','3306':'mysql','2049':'nfs','1433':'ms-sql-s','389':'ldap','123':'ntp'}

class banner_get(object):
  def scan(self,ip_port):
    ip=ip_port.split(':')[0]
    port=int(ip_port.split(':')[1])
    banner = self.grab_banner(ip,port)
    if banner:
      with open(filename,'a+') as f0:
        f0.write(ip_port+'  '+banner+'\n')	  
      return True
    else:
      return False

  def get_response(self, fp, port):
    s= fp.replace("\n", "").replace("\r", "")
    calc=0;unescape=''
    for b in xrange(0, len(s), 16):
      lin = [c for c in s[b : b + 16]]
      pdat = ''.join((c if 32 <= ord(c) <= 126 else '.') for c in lin)
      unescape+=pdat
      calc+=1
    if (not unescape.strip('.')) and str(port) in banners.keys():
      unescape=banners[str(port)]
    return unescape
	
  def grab_banner(self, host, port):
    opts = {}
    opts['timeout'] = 10 #item1
    status, response = self.get_banner(host, port, opts)
    if not status:
      return None
    #response=re.findall(r"^\s*(.*?)\s*$",response)
    if response:
      #return self.get_response(response[0])
      return self.get_response(response,port)
    else:
      return None

  def get_banner(self, host, port, opts={}):
    opts['recv_before'] = True #item2
    socket, nothing, correct, banner = self.tryssl(host, port, "", opts)
    if socket:
      socket.close()
      return True, banner
    return False, banner

  def tryssl(self, host, port, data, opts={}):
    opt1, opt2 = self.bestoption(port) #'tcp','ssl'
    best = opt1
    opts['proto'] = opt1 #item3
    sd, response, early_resp = self.opencon(host, port, data, opts)
    #Try the second option (If udp, then both options are the same; skip it)
    if not sd and opt1 != "udp":
      opts['proto'] = opt2
      sd, response, early_resp = self.opencon(host, port, data, opts)
      best = opt2
    if not sd:
      best = None
    return sd, response, best, early_resp

  def bestoption(self, port):
    if type(port) == dict:
      if port['protocol'] == "udp":
        return "udp", "udp"
      if port['version'] and port['version']['service_tunnel'] and port['version']['service_tunnel']== "ssl":
        return "ssl","tcp"
      if port['version'] and port['version']['name_confidence'] and port['version']['name_confidence'] > 6:
        return "tcp","ssl"
      _port = {}
      _port['number']=port['number'] if port['number'] else 80
      _port['service']=port['service'] if port['service'] else 'http'
      _port['protocol'] = port['protocol'] if port['protocol'] else "tcp"
      _port['state'] = port['state'] if port['state'] else "open"
      _port['version'] = port['version'] if port['version'] else {}
      if self.is_ssl(_port):
        return "ssl","tcp"
    elif type(port) == int:
      if self.is_ssl({'number':port, 'protocol':"tcp", 'state':"open", 'version':{}, 'service':{}}):
        return "ssl","tcp"
    return "tcp","ssl"

  def is_ssl(self, port):
    return self.ssl(port)

  def ssl(self, port):
    LIKELY_SSL_PORTS = {443,465,636,989,990,992,993,994,995,2252,3269,3389,4911,5061,5986,6679,6697,8443,9001,8883}
    LIKELY_SSL_SERVICES={"ftps", "ftps-data", "ftps-control", "https", "https-alt", "imaps", "ircs", "ldapssl", "ms-wbt-server", "pop3s", "sip-tls", "smtps", "telnets", "tor-orport",}
    if (port['version'] and port['version']['service_tunnel'] == "ssl") or self.port_or_service(LIKELY_SSL_PORTS, LIKELY_SSL_SERVICES, {"tcp", "sctp"}, {"open"}, port):
      return True
    else:
      return False

  def port_or_service(self, ports, services, protos, states, port):
    port_checker = self.portnumber(ports, port, protos, states)
    service_checker = self.service(services, port, protos, states)
    if port_checker or service_checker:
      return True
    else:
      return False	  

  def portnumber(self, ports, port, protos={"tcp"}, states={"open"}):
    if type(ports) != set:
      ports = {ports}
    if type(protos) != set:
      protos = {protos}
    if type(states) != set:
      states = {states}
    if self._includes(ports, port['number']) and self._includes(protos, port['protocol']) and self._includes(states, port['state']):
      return True
    else:
      return False
	
  def _includes(self, t, value):
    for elem in t:
      if elem == value:
        return True
    return False	

  def service(self, services, port, protos={"tcp"}, states={"open"}):
    if type(services) != set:
      services = {services}
    if type(protos) != set:
      protos = {protos}
    if type(states) != set:
      states = {states}
    if self._includes(services, port['service']) and self._includes(protos, port['protocol']) and self._includes(states, port['state']):
      return True
    else:
      return False
	
  def opencon(self, host, port, data='', opts={}):
    status, sd = self.setup_connect(host, port, opts)
    if not status:
      return None, sd, None
    if opts['recv_before']:
      status, early_resp = self.read(sd, opts)
    if data and len(data) > 0:
      sd.send(data)
      response = sd.recv(1024)
    else:
      response = early_resp
    if not status:
      sd.close()
      return None, response, early_resp
    return sd, response, early_resp

  def setup_connect(self, host, port, opts):
    #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = socket.socket()
    connect_timeout, request_timeout = self.get_timeouts(host, opts)
    sock.settimeout(connect_timeout)
    if host and opts['proto']:
      try:
        addrs= socket.gethostbyname(host)
        if addrs:
          host = addrs
      except:
        return False, 'error'
    try:
      status = sock.connect_ex((host, port))
    except:
      return False, 'error'
    if status !=0:
      return False, 'error'
    sock.settimeout(request_timeout)
    return True, sock
  
  def read(self, sock, opts):
    try:
      response = sock.recv(1024)
      return True, response
    except:
      return False, 'ERROR'    
	
  def get_timeouts(self, host, opts):
    connect_timeout = 5
    request_timeout = REQUEST_TIMEOUT
    request_timeout = request_timeout + connect_timeout
    return connect_timeout, request_timeout


def main(files):
  for i in files:
    a=banner_get()
    a.scan(ip_port=i)
    
if __name__=='__main__':
  try:
    filename=sys.argv[1]
  except:
    print('usage: %s filename.txt' % sys.argv[0])
    exit()
   
  try:
    files=[i.strip() for i in open(filename).readlines() if len(i)>=10]
  except:
    print('error! file does not exist!')
    exit()
    
  main(files)
