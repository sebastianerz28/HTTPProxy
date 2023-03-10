# Place your imports here
import signal, sys, socket, re
from threading import *
from optparse import OptionParser
from urllib.parse import urlparse
cache = {}
absolutecommands = {"/proxy/cache/enable", "/proxy/cache/disable", "/proxy/cache/flush", "/proxy/blocklist/enable",
                    "/proxy/blocklist/disable", "/proxy/blocklist/flush"}
variablecommandspattern = r""


#General Filtering      #HTTP method   #URL            #Version                    #Headers
requestPattern = r"""(?P<method>\w+) (?P<url>http.*) (?P<httpV>HTTP/\d\.\d)\r*\n*(?P<headers>.*)\r*\n"""



# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# TODO: Put function definitions here
def main(addr, port):
    # Setup listening socket
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSock.bind((addr,port))
    serverSock.listen()
    print("Listening to requests")
    while True:
        #Serve requests when new connections come in
        clientSock, clientAddr= serverSock.accept()
        print("Client:", clientAddr, "connected", "starting thread to handle requests")
        Thread(target=ServeRequest, args=(clientSock, clientAddr)).start()

def ServeRequest(clientSock, clientAddr):

    # Initialize an empty request
    msg = ""
    # Read from the socket until we receive the entire request
    while True:
        # Receive data from the client
        data = clientSock.recv(1024).decode('utf-8')
        # Add the received data to the request
        msg += data
        # Check if we have received the entire request
        if "\r\n\r\n" in msg or "\\r\\n\\r\\n" in msg:
            break

    print("Client sent the request: \n"+msg)
    #Parse the reqest
    parsedInfo = parseHTTPRequest(msg.encode())


    if 'error' not in parsedInfo:
        #TODO: Create function here that handles proxy commands


        #Build reqest send an error if malformed headers
        outBoundRequest = buildRequest(parsedInfo)
        if outBoundRequest == "400 Bad Request":
            clientSock.sendall((("HTTP/1.0 " + outBoundRequest + '\r\n\r\n').encode()))
            clientSock.close()
            return
        requestSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Specific port handling
        print(parsedInfo['host'])
        hostInfo = parsedInfo['host'].split(':')
        try:
            if(len(hostInfo) == 2):
                requestSock.connect((hostInfo[0], int(hostInfo[1])))
            else:
                requestSock.connect((hostInfo[0], 80))
            notTimedOut = True
            #Send the request
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
            finalData = b""
            for s in data:
                finalData += s
            clientSock.sendall(finalData)
            requestSock.close()
        except:
            print("Error")

    else:
        clientSock.sendall(("HTTP/1.0 " + parsedInfo['error'] +'\r\n\r\n').encode())
    clientSock.close()


def parseHTTPRequest(request):

    #Check if request is a match to regex
    regex = re.compile(requestPattern, re.DOTALL)
    regexMatch = regex.match(request.decode())
    #Ensure request follows general format
    if  regexMatch is not None:
        # Ensure it is a GET request
        if 'GET' in regexMatch.group('method'):
            #Check HTTP version
            if regexMatch.group('httpV').split('/')[1] == "1.0":
                print(regexMatch.group('url'))
                #Regex checks for http:// followed by either domains and subdomains or localhost with optional port
                # ensure it ends with a path which is indcated by a / and can have anycharacters after a slash

                if re.match(r"^(?:http:\/\/)(?:(?:\w+\.)+\w+|(?:localhost(?::\d+)?))(\/{1}.*)$", regexMatch.group('url')) is not None:
                #Get regex groups and add them to a dictionary containing everything needed to build a request
                    return {'method': regexMatch.group('method'), 'url': urlparse(regexMatch.group('url'))[2],
                            'version': regexMatch.group('httpV'), 'headers': regexMatch.group('headers'),
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
    #Add GET <PATH> <HTTPVERSION>
    request = "" + valid['method'].strip() + " " + valid['url'].strip() + " " + valid["version"].strip() + "\r\n"
    #Split headers
    valid['headers'] = valid["headers"].strip('\\r\\n')
    skippable = ['\r', "\r\n", "", "\n", "\\r\\n", None]

    allheaders = re.split(r"(\\r\\n)|(\r\n)", valid["headers"])
    for x in skippable:
        if x in allheaders:
            allheaders.remove(x)
    #allHeaders = valid["headers"].split('\\r\\n')
    #Format checks for a-z/A-Z chars followed by a colon followed by a space followed by any characters
    #EX: Chars: Chars
    headerFormat = r"^[a-zA-Z]+-?[a-zA-Z]*:\s[^\r\n]*$"

    #check for malformed headers
    validHeaders = []
    for header in allheaders:
        if header in skippable or header is None:
            continue
        elif not re.match(headerFormat,header):
            return "400 Bad Request"
        elif re.match(headerFormat,header):
            validHeaders.append(header)


    #Check if we need a connection close header and hostname header
    notClosed = False
    conHead = ""
    for header in validHeaders:
        if header.strip() == "Connection: close":
            needsConnectionClose = False
        elif header.startswith("Connection:") and header.strip() != "Connection: close":

            notClosed = True
            conHead = header
        elif header.strip().startswith("Host") == True:
            needsHost = False

    if notClosed:
        validHeaders.remove(conHead)



    if needsHost:
        request += "Host: " + valid['host'].strip() + "\r\n"
    if needsConnectionClose:
        request += "Connection: close\r\n"
    #Add rest of the headers at the bottom
    for header in validHeaders:
        x = header.strip()
        request += header.strip()+ "\r\n"
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
