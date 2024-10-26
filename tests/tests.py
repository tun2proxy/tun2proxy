import glob
import itertools
import os
import subprocess
import time
import unittest
import psutil

import dotenv
import requests

dotenv.load_dotenv()


def get_ip(version=None):
    """provider = 'https://%swtfismyip.com/text'
    prefix = {
        None: '',
        4: 'ipv4.',
        6: 'ipv6.'
    }[version]"""
    provider = 'https://%sipify.org'
    prefix = {
        None: 'api64.',
        4: 'api4.',
        6: 'api6.'
    }[version]
    result = requests.Session().get(provider % prefix).text.strip()
    return result


def get_tool_path():
    default = glob.glob(os.path.join(os.path.dirname(__file__), '..', 'target', '*', 'tun2proxy-bin'))
    default = default[0] if len(default) > 0 else 'tun2proxy-bin'
    return os.environ.get('TOOL_PATH', default)

def sudo_kill_process_and_children(proc):
    try:
        for child in psutil.Process(proc.pid).children(recursive=True):
            if child.name() == 'tun2proxy-bin':
                subprocess.run(['sudo', 'kill', str(child.pid)])
        subprocess.run(['sudo', 'kill', str(proc.pid)])
    except psutil.NoSuchProcess:
        pass

class Tun2ProxyTest(unittest.TestCase):
    @staticmethod
    def _test(ip_version, dns, proxy_var):
        ip_noproxy = get_ip(ip_version)
        additional = ['-6'] if ip_version == 6 else []
        p = subprocess.Popen(
            ['sudo', get_tool_path(), "--proxy", os.getenv(proxy_var), '--setup', '-v', 'trace', '--dns', dns, *additional])
        try:
            time.sleep(1)
            ip_withproxy = get_ip(ip_version)

            assert ip_noproxy != ip_withproxy
        except Exception as e:
            raise e
        finally:
            sudo_kill_process_and_children(p)
            p.terminate()
            p.wait()

    @classmethod
    def add_tests(cls):
        ip_options = [None, 4]
        if bool(int(os.environ.get('IPV6', 1))):
            ip_options.append(6)
        for ip_version, dns, proxy_var in itertools.product(ip_options, ['virtual', 'over-tcp'],
                                                            ['SOCKS5_PROXY', 'HTTP_PROXY']):
            setattr(cls, 'test_ipv%s_dns%s_proxy%s' % (ip_version, dns, proxy_var),
                    lambda self: cls._test(ip_version, dns, proxy_var))


if __name__ == '__main__':
    Tun2ProxyTest.add_tests()
    unittest.main()
