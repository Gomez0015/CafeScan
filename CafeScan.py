# Coded by Raxo (https://github.com/Gomez0015)

# LEGAL DISCLAIMER

# we are not responsible for any illegal use of this tool
# it was made for learning purposes only.

#!/usr/bin/python

import sys, getopt, socket, concurrent.futures, os, time, smb, requests, requests_futures
from datetime import datetime
from concurrent.futures import as_completed
from smb.SMBConnection import SMBConnection
from requests_futures.sessions import FuturesSession
from scapy import *

socket.setdefaulttimeout(5)

openPorts = []
services = { 0: 'unknown', 1: 'TCPMUX', 5: 'RJE', 7: 'ECHO', 18: 'MSP', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 29: 'MSG ICP', 37: 'Time', 42: 'Nameserv', 53: 'DNS', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 115: "SFTP", 139: 'NetBIOS', 143: 'IMAP', 156: 'SQL Server', 161: 'SNMP', 194: 'IRC', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP'}
bannerPayloads = { 'SSH': [' '], 'HTTP': ['GET / HTTP/1.1\r\nHost: www.host.com\r\n\r\n',], 'FTP': [' '], 'POP3': [' '] }
aggressivePayloads = { 'HTTP': ['GET /enum_dir HTTP/1.1\r\nHost: www.host.com\r\n\r\n'], 'SMB': ['SMB'], 'FTP': ['\r\n', 'USER anonymous\r\n', 'PASS anonymous\r\n'], 'POP3': ['', 'USER root\r\n', 'PASS root\r\n'] }
enum_dirList = open('./dicts/enum_dir.txt', "r").read().splitlines()
enum_userList = open('./dicts/enum_user.txt', "r").read().splitlines()
enum_passList = open('./dicts/enum_pass.txt', "r").read().splitlines()
enum_dirListBig = open('./dicts/enum_dirBig.txt', "r").read().splitlines()
hostServices = {}

# User Options
grabBanners = False
aggressiveScan = False
webDirScan = False
target = ''
ports = ''

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Print help message
def printHelp():
	print('Usage: CafeScan [Options]')
	print(f'\n{bcolors.UNDERLINE}MISC:{bcolors.ENDC}')
	print(f'	{bcolors.OKBLUE}-h, --help {bcolors.ENDC}# Help Menu')
	print(f'\n{bcolors.UNDERLINE}TARGET SPECIFICATION:{bcolors.ENDC}')
	print(f'	{bcolors.OKBLUE}-i, --ip-address= {bcolors.ENDC}# Define Target IP')
	print(f'\n{bcolors.UNDERLINE}PORT SPECIFICATION:{bcolors.ENDC}')
	print(f'	{bcolors.OKBLUE}-t, --top-ports {bcolors.ENDC}# Scan Top Ports')
	print(f'	{bcolors.OKBLUE}-a, --all-ports {bcolors.ENDC}# Scan All Ports 0-65535')
	print(f'\n{bcolors.UNDERLINE}SCAN SPECIFICATION:{bcolors.ENDC}')
	print(f'	{bcolors.OKBLUE}--gb, --grab-banners {bcolors.ENDC}# Try To Grab Service Banners')
	print(f'	{bcolors.OKBLUE}--sa, --scan-aggressive {bcolors.ENDC}# Scan Aggressively')
	print(f'	{bcolors.OKBLUE}--sw, --scan-webdir {bcolors.ENDC}# Scan Web Directories/Paths')
	sys.exit()

# Main function
def main(argv):
	global ports

	print('CafeScan v0.0 ( https://github.com/Gomez0015 )\n')

	try:
		# Define CLI arguments
		opts, args = getopt.getopt(argv,"hi:at",["help", "ip-address=","all-ports","top-ports", "grab-banners", "gb", "sa", "scan-webdir", "sw"])
	except getopt.GetoptError:
		printHelp()

	# Check arguments and set variables
	for opt, arg in opts:
		if opt in ("-h", "--help"):
			printHelp()

		elif opt in ("-i", "--ip-address"):
			global target
			target = socket.gethostbyname(arg)

		elif opt in ("-a", "--all-ports"):
			ports = range(65535)

		elif opt in ("-t", "--top-ports"):
			ports = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389]
		
		elif opt in ("--gb", "--grab-banners"):
			global grabBanners
			grabBanners = True
		
		elif opt in ("--sa", "--scan-aggressive"):
			global aggressiveScan
			aggressiveScan = True

		elif opt in ("--sw", "--scan-webdir"):
			global webDirScan
			webDirScan = True

	if(len(target) == 0):
		printHelp()
	if(len(ports) == 0):
		ports = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389]

	startScan()

def startScan():
	global ports
	global openPorts
	global hostServices

	# Print banner
	print("-" * 50)
	print(f"Scanning Target: {bcolors.UNDERLINE}{target}{bcolors.ENDC}")
	print(f"Scanning started at: {bcolors.UNDERLINE}{str(datetime.now())}{bcolors.ENDC}")
	print("-" * 50)

	# if not checkHostReachable():
	# 	print(f"{target} is unreachable")
	# 	sys.exit(101)

	print(f"{bcolors.UNDERLINE}Starting Quick Port Scan{bcolors.ENDC}\n")

	chunkSize = 1000
	x = 0

	loader = loading_cursor()

	while x < len(ports):

		sys.stdout.write(next(loader))
		sys.stdout.flush()
		sys.stdout.write('\b')

		portChunk = ports[x:x+chunkSize];

		x += chunkSize

		# Create a thread pool
		with concurrent.futures.ThreadPoolExecutor(len(portChunk)) as executor:

			# Dispatch all tasks
			results = executor.map(scanPort, portChunk)

			# Report results in order
			for port, is_open in zip(portChunk, results):

				if is_open:
					hostServices[port] = services.get(port, "unknown")
					if(services.get(port, 'unknown') == 'unknown'):
						detectService(port)

					print(f'Port {bcolors.BOLD}{port}{bcolors.ENDC} {bcolors.OKGREEN}open{bcolors.ENDC} | {bcolors.OKBLUE + hostServices[port] if hostServices[port] != "unknown" else bcolors.FAIL + hostServices[port] }{bcolors.ENDC}')
					openPorts.append(port)

	print("-" * 50)

	if(grabBanners):
		print(f"{bcolors.UNDERLINE}Starting Banner Grabbing{bcolors.ENDC}\n")
		bannerGrab()
		print("-" * 50)

	if(aggressiveScan):
		print(f"{bcolors.UNDERLINE}Starting Aggressive Scan{bcolors.ENDC}\n")
		scanAggressively()
		print("-" * 50)

	if(webDirScan == True):
		print(f"{bcolors.UNDERLINE}Starting Web Directory/Path Scan{bcolors.ENDC}\n")


		for port in openPorts:
			if hostServices.get(port, 'none') == 'HTTP':
				print(f"Port {bcolors.BOLD + str(port) + bcolors.ENDC}")
				scanWebDir('http', 80)

		print("-" * 50)

def detectService(port):
	global hostServices
	global socket

	socket.setdefaulttimeout(0.5)
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			       
		s.connect((target, port))

		for service in bannerPayloads:

			try:

				# Try to grab banner/info
				for payload in bannerPayloads[service]:
					payload = payload.replace("www.host.com", target)
						
					s.send(str.encode(payload))
					response = s.recv(1024).decode("utf-8").strip()

					if 'HTTP' in response.upper():
						hostServices[port] = 'HTTP'
					elif 'FTP' in response.upper():
						hostServices[port] = 'FTP'
					elif 'SSH' in response.upper():
						hostServices[port] = 'SSH'

					if hostServices[port] != 'unknown':
						break

				if hostServices[port] != 'unknown':
						break

			except Exception as e:
				pass


def scanWebDir(protocol, port):

	loader = loading_cursor()

	session = FuturesSession()

	futures=[session.get(f'{protocol}://{target}:{port}/{dir}') for dir in enum_dirListBig]

	for future in as_completed(futures):

		sys.stdout.write(next(loader))
		sys.stdout.flush()
		sys.stdout.write('\b')

		resp = future.result()
		if resp.status_code == 200 or resp.status_code == 301:
			print(f'-	{protocol.upper()} {bcolors.OKGREEN + str(resp.status_code) if resp.status_code == 200 else bcolors.WARNING + str(resp.status_code)}{bcolors.ENDC} ( GET /{resp.request.url} )')

def scanAggressively():
	loader = loading_cursor()

	for port in openPorts:

		if (aggressivePayloads.get(hostServices.get(port, 'none'), 'none') != 'none'):
			payloads = aggressivePayloads.get(hostServices.get(port))

			print(f'Port {bcolors.BOLD + str(port) + bcolors.ENDC} | {bcolors.OKBLUE + hostServices.get(port) + bcolors.ENDC}')
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			       
				try:
					# Try to grab banner/info
					s.connect((target, port))

					for payload in payloads:
						
						sys.stdout.write(next(loader))
						sys.stdout.flush()
						sys.stdout.write('\b')

						payload = payload.replace("www.host.com", target)

						if('enum_dir' in payload):
							for dir in enum_dirList:

								sys.stdout.write(next(loader))
								sys.stdout.flush()
								sys.stdout.write('\b')

								res = requests.get(f'http://{target}/{dir}')

								if res.status_code == 200 or res.status_code == 403 or res.status_code == 301:
									print(f'-	HTTP/1.1 {res.status_code} ( GET /{dir} )')

						elif('SMB' in payload):
							smbListShares()
						else:
							s.send(str.encode(payload))
							response = s.recv(1024).decode("utf-8").strip().replace("\n", "\n-	")
							payload = payload.replace("\n", " ").replace("\r", "")

							print(f'-	{response} ( {payload.strip()} )')

				except Exception as e:
					print(f'-	{e}')
					pass

def bannerGrab():
	loader = loading_cursor()

	for port in openPorts:

		sys.stdout.write(next(loader))
		sys.stdout.flush()
		sys.stdout.write('\b')

		if (bannerPayloads.get(hostServices.get(port, 'none'), 'none') != 'none'):
			payloads = bannerPayloads.get(hostServices.get(port))

			print(f'Port {bcolors.BOLD + str(port) + bcolors.ENDC} | {bcolors.OKBLUE + hostServices.get(port) + bcolors.ENDC}')
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			       
				try:
					# Try to grab banner/info
					s.connect((target, port))

					for payload in payloads:
						payload = payload.replace("www.host.com", target)
						
						s.send(str.encode(payload))
						response = s.recv(1024).decode("utf-8").strip()
						payload = payload.replace("\n", " ").replace("\r", "")

						if(hostServices.get(port, 'none') == 'HTTP' or hostServices.get(port, 'none') == 'HTTPS'):
							http_header = [line for line in response.split('\n') if "HTTP/1.1" in line]
							http_server = [line for line in response.split('\n') if "Server:" in line]
							http_title = [line for line in response.split('\n') if "<title>" in line]

							if len(http_header) > 0:
								print(f'-	{http_header[0].strip()}')

							if len(http_server) > 0:
								print(f'-	{http_server[0].strip()}')

							if len(http_title) > 0:
								print(f'-	{http_title[0].strip().replace("<title>", "").replace("</title>", "")}')
						else:
							print(f'-	{os.linesep.join(response.split(os.linesep)[:7])}')

				except Exception as e:
					print(f'-	{e}')
					pass

def scanPort(port):
	
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 	
	       
		try:
			# Return open port
			s.connect((target,port))

			return True
		except:
			return False

def smbListShares():
     smbClient = SMBConnection('', '', target, "")
     if smbClient.connect(target, 139):
         for share in smbClient.listShares():
             print(f"-	{share.name} # {share.comments}")
         return True
     else:
         return False

def checkHostReachable(): 	

	# Ping host to check if it is reachable
	try:
		hostUp = True if os.system("ping -c 1 " + target + " > /dev/null") == 0 else False
		return hostUp
	except socket.gaierror:
		return False
	except socket.error:
		return False

def loading_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor

if __name__ == "__main__":

	try:
		main(sys.argv[1:])
	except KeyboardInterrupt:
		print('\n\n/!\ Keyboard Interrupt')
		try:
			sys.exit(0)
		except SystemExit:
			os._exit(0)