from osfp.lib.config import ALL_OS, OS_DB


def _next_power_of_2(x):
	"""
	Calculate the closest power of 2, greater than the given x.
	:param x: positive integer
	:return: int - the closest power of 2, greater than the given x.
	"""
	return 1 if x == 0 else 2**(x - 1).bit_length()


def get_os_set_from_df(df):
	"""
	Check which Operating Systems could have sent a packet with the given "Don't Fragment" IP flag.
	:param df: bool - Don't Fragment flag of an IP layer
	:return: set - Set of optional Operating Systems
	"""
	return OS_DB["DF"][bool(df)]


def get_os_set_from_ttl(received_ttl):
	"""
	Check which Operating Systems could have sent a packet
	that will be received with the given "Time To Live" field of an IP packet.
	:param received_ttl: int - Time To Live field of an received IP packet
	:return: set - Set of optional Operating Systems
	"""
	os_ttl = _next_power_of_2(received_ttl)
	return OS_DB["TTL"][os_ttl]


def get_os_set_from_ip_parameters(df, ttl):
	"""
	Check which Operating Systems could have sent a packet with the given IP parameters:
	"Don't Fragment" flag and "Time To Live" field
	:param df: bool - Don't Fragment flag of an IP layer
	:param ttl: int - Time To Live field of an IP layer
	:return: set - Set of optional Operating Systems
	"""
 	ip_os_set = ALL_OS
	# DF
	df_os_set = get_os_set_from_df(df)
	ip_os_set.intersection_update(df_os_set)
	# TTL
	ttl_os_set = get_os_set_from_ttl(ttl)
	ip_os_set.intersection_update(ttl_os_set)
	return ip_os_set


def get_os_set_from_win_size(win_size):
	"""
	Check which Operating Systems could have sent a packet with the given "Window Size" field of a TCP layer.
	:param win_size: int - Window Size field of a TCP layer
	:return: set - Set of optional Operating Systems
	"""
	if win_size in OS_DB["Win Size"]:
		return OS_DB["Win Size"][win_size]
	if 2920 <= win_size <= 5840:
		return {"Linux"}
	return {"Windows XP", "Windows 7", "Windows 10"}


def get_os_set_from_mss(mss):
	"""
	Check which Operating Systems could have sent a packet with the given "Max Segment Size" field of a TCP layer.
	:param mss: int - Max Segment Size field of a TCP layer
	:return: set - Set of optional Operating Systems
	"""
	if mss in OS_DB["MSS"]:
		return OS_DB["MSS"][mss]
	return ALL_OS


def get_os_set_from_tcp_parameters(win_size, mss):
	"""
	Check which Operating Systems could have sent a packet with the given TCP parameters:
	"Window Size" field and "Max Segment Size" field
	:param win_size: int - Window Size field of a TCP layer
	:param mss: int - Max Segment Size field of a TCP layer
	:return: set - Set of optional Operating Systems
	"""
	tcp_os_set = ALL_OS
	# Window Size
	win_size_os_set = get_os_set_from_win_size(win_size)
	tcp_os_set.intersection_update(win_size_os_set)
	# Max Segment Size
	mss_os_set = get_os_set_from_mss(mss)
	tcp_os_set.intersection_update(mss_os_set)
	return tcp_os_set