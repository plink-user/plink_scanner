import socket
import nmap
from socket import gethostbyname
from color import *

def nmapscan(ip, port, servicetype):
    try:
        ip = ip.split(":")[0]
        ip = gethostbyname(ip)
    except socket.gaierror:
        pass
    lista = []
    servicetype = {}
    port = port.strip()
    port = port.replace(" ", "")
    port = port.split(",")
    for i in port:
        if "-" in i:
            i = i.split("-")
            for ir in range(int(i[0]), int(i[1]) + 1):
                lista.append(ir)
        else:
            i = int(i)
            lista.append(i)
    for ports in lista:
        nm = nmap.PortScanner()
        result = nm.scan(str(ip), str(ports), "-sV -T4")
        try:
            methed = result["scan"][str(ip)]["tcp"][ports]["reason"]
            service = result["scan"][str(ip)]["tcp"][ports]["product"]

            if str(service) == "":
                pass
            elif "Apache" in str(service):
                servicetype[str(ports)] = 'Apache'
            elif "nginx" in str(service):
                servicetype[str(ports)] = 'nginx'
            elif "IIS" in str(service):
                servicetype[str(ports)] = 'IIS'
            elif "Tomcat" in str(service):
                servicetype[str(ports)] = 'Tomcat'
            elif "JBoss" in str(service):
                servicetype[str(ports)] = 'JBoss'
            elif "weblogic" in str(service):
                servicetype[str(ports)] = 'weblogic'
            else:
                servicetype[str(ports)] = str(service)
        except KeyError:
            servicetype = ""
            pass
    return "", "", servicetype
