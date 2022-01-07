#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from osfp.lib.log import logger
from osfp.lib.methods import test_os_using_icmp, test_os_using_tcp, smb_scan_os
from osfp.lib.survival_detect import SurvialDetect


def main(host):
    verbose = False
    result_set = {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian",
                  "Palm OS", "Centos", "Ubuntu", "Debin"}
    logger.info(f"开始对目标: {host} 进行存活探测")
    is_alive, is_ping = SurvialDetect().run(host)
    if not is_alive:
        logger.info(f"目标：{host} 可能没有存活，检测结束")

    logger.info(f"开始对目标: {host} 进行操作系统识别")

    if is_ping:
        logger.info("开始使用Ping检测操作系统类型")
        icmp_os_set = test_os_using_icmp(host, verbose=verbose)
        result_set.intersection_update(icmp_os_set)
        logger.info(f"Ping检测结果为：{'、'.join(result_set)}")

    if len(result_set) > 2:
        logger.info("开始使用TCP端口检测操作系统类型")
        tcp_os_set = test_os_using_tcp(dst_ip=host, verbose=verbose)
        if len(tcp_os_set) > 0:
            result_set.intersection_update(tcp_os_set)
            logger.info(f"TCP检测结果为：{'、'.join(result_set)}")

    for o in result_set:
        if "win" in o.lower():
            try:
                logger.info("开始使用SMB端口检测操作系统类型")
                result = smb_scan_os(host, timeout=5)
                if result:
                    result_set = [result]
                    logger.info(f"SMB检测结果为：{result_set}")
                break
            except:
                break

    if len(result_set) == 1:
        result_set = list(result_set)[0]
    elif len(result_set) > 1:
        for o in result_set:
            if "win" in o.lower():
                result_set = "Windows"
                break
        else:
            result_set = "Linux"
    else:
        result_set = "Windows"

    logger.info(f"操作系统最终检测结果为：{result_set}")

    return result_set


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(prog="OsDetect", description="识别操作系统指纹")
    parser.add_argument('-t', '--target', help='Detected target (target: ip)')
    example = parser.add_argument_group("examples")
    example.add_argument(action='store_false',
                         dest="python3 cli.py -t 192.168.1.1")
    args = parser.parse_args()
    main(args.target)
