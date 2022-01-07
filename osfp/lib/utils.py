import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
from osfp.lib.db import *

COMMON_TCP_PORTS = [22, 80, 443, 135, 139, 445, 1433, 1521, 3306, 3389, 6379, 7001, 8080]
MAX_RTT = 2
RESEND_COUNT = 2


def get_icmp_reply(dst_ip):
	"""
	Send an ICMP request and wait for the response.
	If the host doesn't answer within MAX_RTT secs - resend.
	If the host doesn't answer within RESEND_COUNT tries - waive.
	:param dst_ip: str - an IPv4 legal ip address - the address of the machine we wish to ping
	:return: ICMP-reply packet (scapy.layers.inet.IP). None if host never answered.
	"""
	ping_request = scapy.IP(dst=dst_ip) / scapy.ICMP()
	ping_reply = scapy.sr1(ping_request, timeout=MAX_RTT, retry=RESEND_COUNT, verbose=0)
	return ping_reply


def send_syn(dst_ip, dst_port):
	"""
	Send a TCP syn and wait for the response.
	If the host doesn't answer within MAX_RTT secs - resend.
	If the host doesn't answer within RESEND_COUNT tries - waive.
	:param dst_ip: str - an IPv4 legal ip address - the address of the machine we wish to syn
	:param dst_port: int - the TCP port to which we wish to send.
	:return: TCP syn-ack packet (scapy.layers.inet.IP). None if host never answered.
	"""
	syn_request = scapy.IP(dst=dst_ip) / scapy.TCP(dport=dst_port)
	reply = scapy.sr1(syn_request, timeout=MAX_RTT, retry=1, verbose=0)
	return reply


def get_syn_ack(dst_ip):
	"""
	Send a TCP syn for each port in COMMON_TCP_PORTS (port scan) and wait for the response.
	If the host doesn't answer within MAX_RTT secs - resend.
	If the host doesn't answer within RESEND_COUNT tries - waive.
	:param dst_ip: str - an IPv4 legal ip address - the address of the machine we wish to syn
	:return: TCP syn-ack packet (scapy.layers.inet.IP). None if host never answered.
	"""
	for port in COMMON_TCP_PORTS:
		reply = send_syn(dst_ip, port)
		if reply is not None and reply.getlayer("TCP").flags == "SA":
			return reply
	return None


def get_ip_parameters(ip_layer):
	"""
	Extract the ip parameters that are relevant to OS detection from an IP layer
	:param ip_layer: an IP packet (scapy.layers.inet.IP)
	:return: tuple - ip parameters. (df, ttl)
	"""
	if ip_layer is None:
		return None
	df = int(format(ip_layer.flags.value, "03b")[1])
	ttl = ip_layer.ttl
	return df, ttl


def os_set_from_ip_layer(ip_layer, verbose=False):
	"""
	Check which Operating Systems could have sent a packet with such an IP layer.
	:param ip_layer: an IP layer of a packet (scapy.layers.inet.IP)
	:param verbose: bool - print relevant information during the process
	:return: set - Set of optional Operating
	"""
	df, ttl = get_ip_parameters(ip_layer)
	if verbose:
		print("DF: {df}, TTL: {ttl}")
	ip_os_set = get_os_set_from_ip_parameters(df, ttl)
	return ip_os_set


def get_tcp_parameters(tcp_layer):
	"""
	Extract the tcp parameters that are relevant to OS detection from a TCP layer
	:param tcp_layer: a TCP packet (scapy.layers.inet.TCP)
	:return: tuple - tcp parameters. (win_size, mss)
	"""
	if tcp_layer is None:
		return None
	win_size = tcp_layer.window
	mss = dict(tcp_layer.options)["MSS"]
	return win_size, mss


def os_set_from_tcp_layer(tcp_layer, verbose=False):
	"""
	Check which Operating Systems could have sent a packet with such a TCP layer.
	:param tcp_layer: a TCP layer of packet (scapy.layers.inet.TCP)
	:param verbose: bool - print relevant information during the process
	:return: set - Set of optional Operating Systems
	"""
	win_size, mss = get_tcp_parameters(tcp_layer)
	if verbose:
		print(f"WIN_SIZE: {win_size}, MSS: {mss}")
	tcp_os_set = get_os_set_from_tcp_parameters(win_size, mss)
	return tcp_os_set