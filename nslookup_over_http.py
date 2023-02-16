"""
Implementation of nslookup server using scapy, over http.
Example requests (run the server and type in the browser):
    http://127.0.0.1:8153/www.youtube.com - resolve domain name
    http://127.0.0.1:8153/reverse/172.217.23.110 - resolve ip address


Author: Noam Shushan
"""

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP

# constants:
SERVER_IP = '0.0.0.0'
DNS_IP = '1.1.1.1'
PORT = 8153
DNS_PORT = 53
SRC_DNS_PORT = 5353
SOCKET_TIMEOUT = 0.1
REQUEST_TIMEOUT = 2
TYPE_A = 1
TYPE_PTR = 12


def resolve_ip_address(ip_address):
    """
    resolve ip address to domain name
    :param ip_address: the ip address to resolve
    :return: domain names of the ip address
    """

    # reverse the ip address and add the in-addr.arpa domain for PTR request
    reverse_ip_address = '.'.join(
        reversed(ip_address.split('.'))) + '.in-addr.arpa'

    # create dns request using scapy
    dns_req = IP(dst=DNS_IP) \
        / UDP(dport=DNS_PORT, sport=SRC_DNS_PORT) \
        / DNS(qdcount=1, rd=1, qd=DNSQR(qname=reverse_ip_address, qtype=TYPE_PTR))

    while True:
        # send the request and wait for the answer
        answer = sr1(dns_req, timeout=REQUEST_TIMEOUT)
        # if we got an answer break the loop, else try again (timeout exception)
        if answer is not None:
            break

    # get the domain name from the answer
    result = ''
    for i in range(answer[DNS].ancount):
        result += answer[DNSRR][i].rdata.decode() + '\r\n'

    return result if result != '' else f'not found "{ip_address}"'


def resolve_domain_name(domain_name):
    """
    resolve domain name to ip address
    :param domain_name: the domain name to resolve
    :return: ip addresses of the domain name
    """
    dns_req = IP(dst=DNS_IP) \
        / UDP(dport=DNS_PORT, sport=SRC_DNS_PORT) \
        / DNS(qdcount=1, rd=1, qd=DNSQR(qname=domain_name, qtype=TYPE_A))

    while True:
        # send the request and wait for the answer
        answer = sr1(dns_req, timeout=REQUEST_TIMEOUT)
        # if we got an answer break the loop, else try again (timeout exception)
        if answer is not None:
            break

    # get the ip address from the answer
    result = ''
    for i in range(answer[DNS].ancount):
        if answer[DNSRR][i].type == TYPE_A:
            result += answer[DNSRR][i].rdata + '\r\n'

    return result if result != '' else f'not found "{domain_name}"'


def internet_on(host="8.8.8.8", port=53, timeout=3):
    """
    Host: 8.8.8.8 (google-public-dns-a.google.com)
    OpenPort: 53/tcp
    Service: domain (DNS/TCP)
    """
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error as ex:
        print(ex)
        return False


def validate_ip(ip_address):
    """
    validate ip address
    :param ip_address: the ip address to validate
    :return: True and valid message if valid, else False and error message
    """
    not_valid_msg = f"IP address '{ip_address}' is not valid"

    # check for empty or null string
    if not ip_address:
        return False, not_valid_msg

    parts = ip_address.split(".")

    if len(parts) != 4:
        return False, not_valid_msg

    for part in parts:
        if not isinstance(int(part), int):
            return False, not_valid_msg

        if int(part) < 0 or int(part) > 255:
            return False, not_valid_msg

    return True, f"IP address '{ip_address}' is valid"


def validate_domain_name(domain_name):
    """
    validate domain name
    :param domain_name: the domain name to validate
    :return: True and valid message if valid, else False and error message
    """
    not_valid_msg = f"Domain name '{domain_name}' is not valid"

    # check for empty or null string
    if not domain_name:
        return False, not_valid_msg

    if len(domain_name) > 255:
        return False, not_valid_msg

    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    if all(allowed.match(x) for x in domain_name.split(".")):
        return True, f"Domain name '{domain_name}' is valid"
    else:
        return False, not_valid_msg


def validate_http_request(request):
    """
    validate http request
    :param request: the http request to validate
    :return: True and valid message if valid, else False and error message
    """
    first_line = request.split('\r\n')[0]
    if not first_line.startswith('GET'):
        return False, ''

    split_request = first_line.split()
    if len(split_request) != 3:
        return False, ''
    if 'HTTP' not in split_request[2]:
        return False, ''

    resource = split_request[1]
    # we not support other auto requests
    if resource == '/favicon.ico':
        return False, ''

    return True, resource


def handle_normal_request(client_socket, domain_name):
    """
    handle normal request and send the ip addresses to the client if there is no error
    :param client_socket: the client socket
    :param domain_name: domain name to resolve
    """
    valid_dns, msg = validate_domain_name(domain_name)
    if valid_dns:
        print(msg)
        # resolve the domain name
        ip_addresses = resolve_domain_name(domain_name)

        # create http header and response
        http_header = get_http_header(len(ip_addresses))
        http_response = http_header + ip_addresses

        # send the ip address to the client
        client_socket.send(http_response.encode())
    else:
        # send bad request to the client
        bad_request(client_socket, msg)


def handle_reverse_request(client_socket, ip_address):
    """
    handle reverse request and send the domain name to the client if there is no error
    :param client_socket: the client socket
    :param ip_address: ip address to resolve
    """
    valid_address, msg = validate_ip(ip_address)
    if valid_address:
        print(msg)
        # resolve the ip address
        domain_names = resolve_ip_address(ip_address)

        # create http header and response
        http_header = get_http_header(len(domain_names))
        http_response = http_header + domain_names

        # send the domain name to the client
        client_socket.send(http_response.encode())
    else:
        # send bad request to the client
        bad_request(client_socket, msg)


def get_http_header(content_length):
    """get http header for a OK response"""
    return 'HTTP/1.1 200 OK\r\n' + 'content-type: text/plain\r\n' + f"content-length: {content_length}" + '\r\n\r\n'


def handle_client_request(resource, client_socket):
    """handle client request"""
    # check if the resource is reverse
    try:
        if not internet_on():
            bad_request(client_socket, 'No internet connection')
            return
        # check if the request is reverse mapping
        if '/reverse' in resource:
            # get the ip address
            ip_address = resource.split('/reverse/')[1]
            # handle the reverse request
            handle_reverse_request(client_socket, ip_address)
        else:
            # get the domain name
            domain_name = resource.split('/')[1]
            # handle the normal request (resolve domain name)
            handle_normal_request(client_socket, domain_name)
    except:
        # in any case of unknown exception send bad request to the client
        bad_request(client_socket, 'Bad Request')


def bad_request(client_socket, msg=''):
    """send bad request to the client"""
    if msg:
        msg += '\r\n'
    client_socket.send(f'HTTP/1.1 400 Bad Request\r\n\r\n{msg}'.encode())


def handle_client(client_socket):
    """handle client request"""
    while True:
        # receive client request
        client_request = client_socket.recv(1024).decode()

        # check if request is valid HTTP request
        valid_http, resource = validate_http_request(client_request)
        if valid_http:
            print('Got a valid HTTP request\n')
            print(f'client request: {resource}\n')
            handle_client_request(resource, client_socket)
        else:
            req = client_request.split('\r\n')[0]
            print(f'Error: Not a valid HTTP request\n{req}\n')
            break

    print('Closing client connection\n')
    client_socket.close()


def main():
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind socket
    server_socket.bind((SERVER_IP, PORT))

    # listen to localhost
    server_socket.listen()

    client_socket = None
    print(f"Listening for connections on port {PORT}...")
    try:
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                print('New connection received\n')
                client_socket.settimeout(SOCKET_TIMEOUT)

                handle_client(client_socket)
            except socket.timeout:
                print('Connection timed out\n')
                client_socket.close()
                continue
            except Exception as e:
                print(e)
                client_socket.close()
                break
    finally:
        print('Closing server')
        server_socket.close()


if __name__ == '__main__':
    main()
