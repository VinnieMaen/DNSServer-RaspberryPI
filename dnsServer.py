import socket

port = 53
ip = "10.128.52.21"

socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #AF_INET geeft aan dat we data willen sturen over IPV4. DGRAM geeft python aan dat we UDP willen gebruiken.
socket.bind((ip, port))

DATA = {
    "google.com." : {
        "a":[
            { "name": "@", "ttl": 400, "value": "142.250.179.174" },
        ]
    },
    "vinitylabs.com." : {
        "a" : [
            { "name": "@", "ttl": 400, "value": "185.189.182.198"},
            { "name": "@", "ttl": 400, "value": "192.227.128.180"},
        ]
    }
}

def getFlags(data):
    byte1 = bytes(data[:1]) #First byte

    QR = "1" #1 wilt zeggen response, 0 wil zeggen query

    OPCODE = ""

    for bit in range(1, 5):
        OPCODE += str(ord(byte1)&(1<<bit))

    AA = "1"

    TC = "0"

    RD = "0"

    RA = "0"

    Z = "000" #3 nullen want 3 bits

    RCODE = "0000" #4 nullen want 4 bits

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder="big")+int(RA+Z+RCODE, 2).to_bytes(1, byteorder="big")

def getDomain(data):
    state = 0
    expectedLength = 0
    domainString = ""
    domainParts = []
    x = 0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainString += chr(byte)
            x += 1
            
            if x == expectedLength:
                domainParts.append(domainString)
                domainString = ""
                state = 0
                x = 0

            if byte == 0:
                domainParts.append(domainString)
                break

        else:
            state = 1
            expectedLength = byte
        
        y += 1

    questionType = data[y:y+2]

    return (domainParts, questionType)

def getRecs(domain):
    global DATA
    
    domain_name = ".".join(domain[0])
    return (DATA[domain_name]["a"], "a", domain[0])

def buildDnsQuestion(domainName, rectype):
    qbyte = b''

    for part in domainName:
        length = len(part)
        qbyte += bytes([length])

        for char in part:
            qbyte += ord(char).to_bytes(1, byteorder="big")
        
    qbyte += (1).to_bytes(2, byteorder="big")
    qbyte += (1).to_bytes(2, byteorder='big')

    return qbyte

def rectoBytes(domain, rectype, ttl, val):
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(ttl).to_bytes(4, byteorder="big")

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in val.split('.'):
            rbytes += bytes([int(part)])
    
    return rbytes

def buildResponse(data):
    #Transaction ID header
    transID = data[:2] #String van bytes. We nemen de eerste 2 bytes want dit is de locatie van transaction ID
    
    #Flags header
    flags = getFlags(data[2:4]) #3e en 4e byte doorgeven, zie wireshark waarom deze twee

    #QCount
    QDCOUNT = b'\x00\x01'

    #Answercount
    ANCOUNT = len(getRecs(getDomain(data[12:]))[0]).to_bytes(2, byteorder="big") #12: zodat we niet de headers nemen maar de queries data
    
    #Nameserver count
    NSCOUNT = (0).to_bytes(2, byteorder="big")
    
    #Additional count
    ARCOUNT = (0).to_bytes(2, byteorder="big")

    dnsHeader = transID+flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT

    dnsBody = b''

    records, rectype, domainName = getRecs(getDomain(data[12:]))

    dnsQuestion = buildDnsQuestion(domainName, rectype)

    for record in records:
        dnsBody += rectoBytes(domainName, rectype, record["ttl"], record["value"])

    return dnsHeader + dnsQuestion + dnsBody

while True:
    data, addr = socket.recvfrom(512) #512 bytes
    socket.sendto(buildResponse(data), addr)
