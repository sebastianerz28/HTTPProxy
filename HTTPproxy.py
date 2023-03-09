# Place your imports here
import signal, sys, socket, re
from threading import *
from optparse import OptionParser
from urllib.parse import urlparse
cache = {}
requestPattern = r"""(?P<method>\w+) (?P<url>http.*) (?P<httpV>HTTP/\d\.\d)\r*\n*(?P<headers>.*)\r*\n"""
# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# TODO: Put function definitions here
def main(addr, port):
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.bind((addr,port))
    serverSock.listen()
    print("Listening to requests")
    while True:
        clientSock, clientAddr= serverSock.accept()
        thread = Thread(target=ServeRequest, args=(clientSock, clientAddr))
        thread.start()


def ServeRequest(clientSock, clientAddr):
    print("Client:", clientAddr, "connected")
    msg = clientSock.recv(1024)
    print(msg.decode())
    parsedInfo = parseHTTPRequest(msg)
    if 'error' not in parsedInfo:
        outBoundRequest = buildRequest(parsedInfo)
        if outBoundRequest == "400 Bad Request":
            clientSock.sendall((("HTTP/1.0 " + outBoundRequest + '\r\n\r\n').encode()))
            clientSock.close()
            return
        requestSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(parsedInfo['host'])
        hostInfo = parsedInfo['host'].split(':')
        if(len(hostInfo) == 2):
            requestSock.connect((hostInfo[0], int(hostInfo[1])))
        else:
            requestSock.connect((hostInfo[0], 80))
        notTimedOut = True
        requestSock.send(outBoundRequest.encode())
        data = []
        while notTimedOut:
            try:
                currData = requestSock.recv(4096)
                if len(currData) == 0:
                    break
                data.append(currData)
            except:
                notTimedOut = False
        x = ""
        for s in data:
            x += s.decode()
        clientSock.sendall(x.encode())
        requestSock.close()

    else:
        clientSock.sendall(("HTTP/1.0 " + parsedInfo['error'] +'\r\n\r\n').encode())
    clientSock.close()




def parseHTTPRequest(request):

    #Check if request is a match to regex
    regex = re.compile(requestPattern, re.DOTALL)
    regexMatch = regex.match(request.decode())
    if  regexMatch is not None:
        if 'GET' in regexMatch.group('method'):
            if regexMatch.group('httpV').split('/')[1] == "1.0":
                print(regexMatch.group('url'))
                if re.match(r"^(?:http:\/\/(?:\w+\.)+\w+\/|http:\/\/localhost(?::\d+)?\/)(?:[^\/]+\/)*[^\/]+$", regexMatch.group('url')) is not None:
                #Get regex groups and add them to a dictionary containing everything needed to build a request
                    return {'method': regexMatch.group('method'), 'url': urlparse(regexMatch.group('url'))[2], 'version': regexMatch.group('httpV'), 'headers': regexMatch.group('headers'),
                            'host': urlparse(regexMatch.group('url'))[1]}
                else:
                    return {'error' : "400 Bad Request"}
            else:
                return {'error': "400 Bad Request"}
        else:
            return {'error': "501 Not Implemented"}
    else:
        return {'error': "400 Bad Request"}
    # Split the request into lines
def buildRequest(valid):
    needsConnectionClose = True
    needsHost = True
    #Add GET / <HTTPVERSION>
    request = "" + valid['method'].strip() + " " + valid['url'].strip() + " " + valid["version"].strip() + "\r\n"
    #Split headers
    valid['headers'] = valid["headers"].strip('\\r\\n')
    skippable = ['\r', "\r\n", "", "\n", "\\r\\n"]
    allHeaders = valid["headers"].split('\\r\\n')
    headerFormat = r"^[a-zA-Z]+-?[a-zA-Z]*:\s[^\r\n]*$"

    for header in allHeaders:
        if header in skippable:
            continue
        elif not re.match(headerFormat,header):
            return "400 Bad Request"
        #splitHeader = header.split()
    #    if(len(splitHeader) < 2):
     #       return "400 Bad Request"
      #  else:
       #     for x in splitHeader:
        #        if
    #Check if we need a connection close header and hostname header
    for header in allHeaders:
        header.split()
        if header.strip() == "Connection: close":
            needsConnectionClose = False
        elif header.strip().startswith("Host") == True:
            needsHost = False

    if needsHost:
        request += "Host: " + valid['host'].strip() + "\r\n"
    if needsConnectionClose:
        request += "Connection: close\r\n"
    #Add rest of the headers at the bottom
    for header in allHeaders:
        x = header.strip()
        if x != "" and x != " " and x != "\r" and x != "\r\n":
            request += x.strip() + "\r\n"
    request += "\r\n"
    return request

# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

# TODO: Set up sockets to receive requests

# IMPORTANT!
# Immediately after you create your proxy's listening socket add
# the following code (where "skt" is the name of the socket here):
# skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Without this code the autograder may cause some tests to fail
# spuriously.
if __name__ == '__main__':
    main(address,port)
