import socket
import ipaddress

class IP_SERVICE():



    @staticmethod
    def domain_to_ip(domain: str) -> list:
        """
        Возвращает список словарей
        [   {'ip_addres': str,
            'ip_version': str,
            'real_name': str
            },

            {'ip_addres': str,
            'ip_version': str,
            'real_name': str
            }
        ] 
        всех полученных IPv4 && IPv6
        """

        info_ip = socket.getaddrinfo(host=domain, port=0, family=socket.AF_UNSPEC, flags=socket.AI_CANONNAME, type=socket.SOCK_STREAM)
        scan_result = []
        for item in info_ip:
            family, socktype, proto, canonname, addr = item
            IPv = "IPv6" if family == socket.AF_INET6 else "IPv4"
            if canonname == '':
                canonname = domain
            result = {
                "ip_addres": addr[0],
                "ip_version": IPv,
                "real_name": canonname
            }
            scan_result.append(result)
        print(scan_result)
        return scan_result


    @staticmethod
    async def make_CIDR(ip: str) -> list:
        """
        Возвращает все список всех ip`s на подсети
        """
        net = ipaddress.ip_network(ip, strict=False)
        
        all_ips = []
        
        for single_ip in net.hosts():  # .hosts() сразу откидывает служебные .0 и .255
            all_ips.append({'ip_addres': str(single_ip)})
            
            if len(all_ips) >= 1024:
                break
                
        return all_ips


