#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from osfp.lib.log import logger
from osfp.lib.methods import ALL_OS, test_os_using_icmp, test_os_using_tcp, smb_scan_os


def main(host, methods=["icmp", "tcp", "smb"]):
    verbose = False
    result_set = ALL_OS

    logger.info(f"开始对目标: {host} 进行操作系统识别")

    logger.info("开始使用Ping检测操作系统类型")
    icmp_os_set = test_os_using_icmp(host, verbose=verbose)
    result_set.intersection(icmp_os_set)
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
    elif len(result_set) > 2:
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
    # print(main("192.168.1.135"))
    # print(main("192.168.0.161"))
    # print(main("192.168.0.87"))
    # print(main("192.168.1.51"))
    # print(main("10.10.16.124"))
    # print(main("10.10.16.72"))
    # main("10.10.16.124")
    # import sys
    # main(sys.argv[1])
    main("52.18.1.159")