import socket

# Mock /etc/hosts file implementation:
# https://stackoverflow.com/questions/29995133/python-requests-use-navigate-site-by-servers-ip


def custom_resolver(etc_hosts, builtin_resolver):
    def wrapper(*args, **kwargs):
        try:
            return etc_hosts[args[:2]]
        except KeyError:
            return builtin_resolver(*args, **kwargs)
    return wrapper


def bind_ip(etc_hosts, domain_name, port, ip):
    key = (domain_name, port)
    value = (
        socket.AddressFamily.AF_INET,
        socket.SocketKind.SOCK_STREAM,
        6,
        '',
        (ip, port))
    etc_hosts[key] = [value]
    return etc_hosts