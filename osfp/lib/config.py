#!/usr/bin/env python
# -*- coding: utf-8 -*-

ALL_OS = {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian", "Palm OS", "Centos 7", "Ubuntu"}

OS_DB = {
	"DF": {
		True: {"FreeBSD", "Linux", "Windows XP", "Windows 7", "Windows 10", "Centos 7", "Ubuntu"},
		False: {"FreeBSD", "Symbian", "Palm OS", "Linux", "Windows XP", "Windows 7", "Windows 10", "Centos 7", "Ubuntu"}
	},
	"TTL": {
		64:	{"Linux", "FreeBSD", "Centos 7", "Ubuntu"},
		128: {"Windows XP", "Windows 7", "Windows 10"},
		256: {"Symbian", "Palm OS", "Cisco IOS"}
	},
	"Win Size": {
		8192: {"Symbian", "Windows 7"},
		14600: {"Linux"},
		16348: {"Palm OS"},
		64240: {"Linux", "Ubuntu"},
		65392: {"Windows 10"},
		65535: {"FreeBSD", "Windows XP", "Windows 10"},
		65550: {"FreeBSD"},
		29200: {"Centos 7"},
		None: ALL_OS
	},
	"MSS": {
		1350: {"Palm OS"},
		1440: {"Windows XP", "Windows 7", "Windows 10"},
		1460: {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian"},
		1200: {"Centos 7", "ubuntu", "Windows 7"}
	}
}