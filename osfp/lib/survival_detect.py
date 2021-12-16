#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
from osfp.lib.utils import *


class SurvialDetect(object):

    def _ping(self, host):
        """通过ping命令判断存活"""
        is_alive = False

        try:
            icmp_reply = get_icmp_reply(host)
            ip_layer = icmp_reply.getlayer("IP")
            df, ttl = get_ip_parameters(ip_layer)
            ttl_os_set = get_os_set_from_ttl(ttl)
            if ttl_os_set:
                is_alive = True
        except:
            pass

        return is_alive

    def _scan_port(self, host):
        """通过扫描端口判断主机是否存活"""
        is_alive = False

        tcp_ports = [22, 80, 443, 135, 139, 445, 3306, 6379, 3389]
        socket.setdefaulttimeout(2)
        for port in tcp_ports:
            try:
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp.connect((host, port))
                is_alive = True
                break
            except Exception:
                pass

        return is_alive

    def run(self, host):
        is_alive = self._ping(host)
        is_ping = False
        if is_alive:
            is_ping = True

        if not is_alive:
            is_alive = self._scan_port(host)
        return is_alive, is_ping


if __name__ == '__main__':
    print(SurvialDetect().run("10.10.16.96"))
