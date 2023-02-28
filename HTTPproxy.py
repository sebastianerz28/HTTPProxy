# Place your imports here
import signal, sys, socket, re
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
    while True:
        print("Listening to requests")
        clientSock, clientAddr= serverSock.accept()
        print("Client:", clientAddr,"connected")
        msg = clientSock.recv(1024)
        valid = parseHTTPRequest(msg)
        if valid['error'] is None:
            outBoundRequest = buildRequest(valid)


        else:
            clientSock.send(valid['error'])




def parseHTTPRequest(request):
    regex = re.compile(requestPattern, re.DOTALL)
    regexMatch = regex.match(request)
    if  regexMatch is not None:
        if 'GET' in regexMatch.group('method'):
            return {'method': regexMatch.group('method'), 'url': urlparse(regexMatch.group('url'))[2], 'version': regexMatch.group('httpV'), 'headers': regexMatch.group('headers'),
                    'host': urlparse(regexMatch.group('url'))[1]}
        else:
            return {'error': "501 Not implemented"}
    else:
        return {'error': "400 Bad request"}
    # Split the request into lines
def buildRequest(valid):
    needsConnectionClose = True
    needsHost = True
    request = "" + valid['method'].strip() + " " + valid['url'].strip() + " " + valid["version"].strip() + "\r\n"
    allHeaders = valid["headers"].splitlines()
    for header in allHeaders:
        if header.strip() == "Connection: close":
            needsConnectionClose = False
        elif header.strip().startswith("Host") == True:
            needsHost = False

    if needsHost:
        request += "Host: " + valid['host'].strip() + "\r\n"
    if needsConnectionClose:
        request += "Connection: close\r\n"
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
