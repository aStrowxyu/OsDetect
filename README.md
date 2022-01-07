# OsDetect

识别通过ping、TCP和连接中的特性和SMB服务识别操作系统类型和版本

## 使用

```sh
usage: OsDetect [-h] [-t TARGET]

识别操作系统指纹

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Detected target (target: ip)

examples:
  python3 cli.py -t 192.168.1.1

```
