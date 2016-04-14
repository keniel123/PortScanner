import optparse
from socket import *
from threading import *
import re
import subprocess
import ast

ports=[21,22,80,8080,50,53,21, 23, 25, 80, 113, 137, 139, 555, 666, 1001, 1025, 1026, 1028, 1243, 2000, 500,
    6667, 6670, 6711, 6776, 6969, 7000, 8080,25,135, 137, 139, 389, 445, 1024, 1025,
    1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050]

def bannerGrab(ip_address,port):
    try:
        bannerSocket=socket(AF_INET, SOCK_STREAM)
        bannerSocket.connect((ip_address,port))
        bannerSocket.send("Hello\r\n")
        banner = bannerSocket.recv(1024)
        if banner:
            print'[+] Connection to port ' + str(port) + ' successful! \n'
            print 'Network Banner: ' + banner + "\n"
            checkBanner(banner)
    except Exception:
            print '[-] Connection to ' + ip_address + ' port ' + str(port) + ' unsuccessful \n'
    finally:
        bannerSocket.close()

def checkBanner(banner):
    f = open("vuln-banners.txt",'r')
    for line in f.readlines():
        if line.strip('\n') in banner:
            print "[+] Server is vulnerable: "+banner 


def extractIPs(fileContent):
    pattern = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
    ips = [each[0] for each in re.findall(pattern, fileContent)]
    for item in ips:
        location = ips.index(item)
        ip = re.sub("[ ()\[\]]", "", item)
        ip = re.sub("dot", ".", ip)
        ips.remove(item)
        ips.insert(location, ip)
    return ips

def readFile(fileName):
    myFile = open(fileName)
    fileContent = myFile.read()
    IPs = extractIPs(fileContent)
    #print "Original file content:\n{0}".format(fileContent)
    #print "--------------------------------"
    ip="{0}".format(IPs)
    return ip
    #print "Parsed results:\n{0}".format(IPs)

def getIp_Addr(filename):
    with open(filename, 'w') as f:
        PIPE, STDOUT = subprocess.PIPE, subprocess.STDOUT
        subprocess.Popen(['arp', '-a'], stdin=PIPE, stdout=f, stderr=STDOUT)


def portScan(tgtHost):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print "[-] Cannot resolve '%s': Unknown host"%tgtHost
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print '\n[+] Scan Results for: ' + tgtName[0]
    except:
        print '\n[+] Scan Results for: ' + tgtIP
    setdefaulttimeout(1)
    for tgtPort in ports:
        t = Thread(target=bannerGrab, args=(tgtHost, int(tgtPort)))
        t.start()


def main():

    parser = optparse.OptionParser('usage%prog '+\
    '-H <target host>')
    parser.add_option('-H', dest='tgtHost', type='string', \
    help='specify target host')
    (options, args) = parser.parse_args()
    getIp_Addr('arptable.txt')
    targetHost = options.tgtHost
    if (targetHost == None):
        print parser.usage
        exit(0)
    portScan(targetHost)
    ips = ast.literal_eval(readFile('arptable.txt'))
    for i in ips:
        portScan(i)

if __name__== "__main__":
    main()
