#!/usr/bin/env python
# -*- coding: utf-8 -*-

ALL_OS = {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian", "Palm OS", "Centos", "Ubuntu", "Debain"}

OS_DB = {
	"DF": {
		True: {"FreeBSD", "Linux", "Windows XP", "Windows 7", "Windows 10", "Centos", "Ubuntu", "Debain"},
		False: {"FreeBSD", "Symbian", "Palm OS", "Linux", "Windows XP", "Windows 7", "Windows 10", "Centos", "Ubuntu"}
	},
	"TTL": {
		64:	{"Linux", "FreeBSD", "Centos", "Ubuntu"},
		128: {"Windows XP", "Windows 7", "Windows 10"},
		256: {"Symbian", "Palm OS", "Cisco IOS", "Debain"}
	},
	"Win Size": {
		8192: {"Symbian", "Windows 7"},
		14600: {"Linux"},
		16348: {"Palm OS"},
		64240: {"Linux", "Ubuntu", "Centos"},
		65392: {"Windows 10"},
		65535: {"FreeBSD", "Windows XP", "Windows 10"},
		65550: {"FreeBSD"},
		29200: {"Centos"},
		26883: {"Debain"},
		None: {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian", "Palm OS", "Centos", "Ubuntu", "Debain"}
	},
	"MSS": {
		1350: {"Palm OS"},
		1440: {"Windows XP", "Windows 7", "Windows 10"},
		1460: {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian"},
		1200: {"Centos", "Ubuntu", "Windows 7", "Debain"}
	}
}