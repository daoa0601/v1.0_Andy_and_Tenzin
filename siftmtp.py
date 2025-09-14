#python3

import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		self.msg_hdr_rsv = b'\x00\x00'
		self.size_msg_hdr_rsv = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rdn = 6
		# --------- STATE ------------
		self.snd_num = 1
		self.rcv_num = 1
		self.session_key = None

		self.peer_socket = peer_socket

	def key_set(self, key):
		self.session_key = key
		print(self.session_key.hex())

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rdn'], i = msg_hdr[i:i+self.size_msg_hdr_rdn], i+self.size_msg_hdr_rdn
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')
			
		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		
		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			en_msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		
		
		# Getting the sequence number
		sqn_num = parsed_msg_hdr['sqn']
		sequence_number = int.from_bytes(sqn_num, byteorder='big')
		ran_byte = parsed_msg_hdr['rdn']

		# Verifies that the sequence number is larger than than the last received sequence number
		if sequence_number < self.rcv_num:
			raise SiFT_MTP_Error("Sequence Number is larger than the last received sequence number")

		if parsed_msg_hdr['typ'] == self.type_login_req:
			
			etk = en_msg_body[-256:]
			tag = en_msg_body[-268:]
			authtag = tag[:12]
			en_payload = en_msg_body[:-268]
			private_key = RSA.import_key(open("private.pem").read())
			
			# Decrypt the session key with the private RSA key
			cipher_rsa = PKCS1_OAEP.new(private_key)
			temp_key = cipher_rsa.decrypt(etk)
			self.key_set(temp_key)

			# Decrypt the data with the AES session key
			# Getting the nonce by concatenating the sequence number and the random bytes
			nonce = sqn_num + ran_byte
			
			cipher_gcm = AES.new(temp_key, AES.MODE_GCM, nonce = nonce, mac_len = 12)
			cipher_gcm.update(msg_hdr)
			msg_body = cipher_gcm.decrypt_and_verify(en_payload, authtag)
			

			# DEBUG 
			if self.DEBUG:
				print('MTP message received (' + str(msg_len) + '):')
				print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
				print('BDY (' + str(len(msg_body)) + '): ')
				print(msg_body.hex())
				print('------------------------------------------')
			# DEBUG 

			if len(msg_body) != msg_len - self.size_msg_hdr - 256 - 12: 
				raise SiFT_MTP_Error('Incomplete message body reveived')
		else:
			tag = en_msg_body[-12:]
			en_payload = en_msg_body[:-12]
			
			# Decrypt the data with the AES session key
			# Getting the nonce by concatenating the sequence number and the random bytes
			nonce = sqn_num + ran_byte

			cipher_gcm = AES.new(self.session_key, AES.MODE_GCM, nonce = nonce, mac_len = 12)
			cipher_gcm.update(msg_hdr)
			msg_body = cipher_gcm.decrypt_and_verify(en_payload, tag)
			# DEBUG 
			if self.DEBUG:
				print('MTP message received (' + str(msg_len) + '):')
				print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
				print('BDY (' + str(len(msg_body)) + '): ')
				print(msg_body.hex())
				print('------------------------------------------')
			# DEBUG 

			if len(msg_body) != msg_len - self.size_msg_hdr -12: 
				raise SiFT_MTP_Error('Incomplete message body reveived')
		# If all verifications are passed, change the last received sequence number
		# to the current sequence number of the sent message.
		self.rcv_num = sequence_number
		return parsed_msg_hdr['typ'], msg_body


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		# build message
		#msg_size = self.size_msg_hdr + len(msg_payload)
		#msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		#msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len 
		if(msg_type == self.type_login_req):
			temp_key = Random.get_random_bytes(32)
			self.key_set(temp_key)
			recipient_key = RSA.import_key(open("zac+stefan.pem").read())
			# Encrypt the session key with the public RSA key
			cipher_rsa = PKCS1_OAEP.new(recipient_key)
			enc_temp_key = cipher_rsa.encrypt(temp_key)
			
			# Getting the nonce by cryptographically getting 6 random bytes
			# alongside the sequence number
			msg_rand = Random.get_random_bytes(6)
			nonce = self.snd_num.to_bytes(length=2, byteorder='big') + msg_rand
			# Encrypt the data with the AES session key
			cipher_gcm = AES.new(self.session_key, AES.MODE_GCM, nonce =nonce, mac_len = 12)

			# Building the header
			msg_size = self.size_msg_hdr + len(msg_payload) + 12 + len(enc_temp_key)
			
			msg_hdr = self.msg_hdr_ver + msg_type + msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big') + nonce + self.msg_hdr_rsv

			cipher_gcm.update(msg_hdr)
			ciphertext, tag = cipher_gcm.encrypt_and_digest(msg_payload)
			# DEBUG 
			if self.DEBUG:
				print('MTP message to send (' + str(msg_size) + '):')
				print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
				print('BDY (' + str(len(msg_payload)) + '): ')
				print(msg_payload.hex())
				print('MAC (' + str(len(tag)) + '): ' + tag.hex())
				print('ETK (' + str(len(enc_temp_key)) + '): ' + enc_temp_key.hex())
				print('------------------------------------------')
			# DEBUG 
			# try to send
			try:
				self.send_bytes(msg_hdr + ciphertext + tag + enc_temp_key)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
			self.snd_num += 1
		else:
			
			# Getting the nonce by cryptographically getting 6 random bytes
			# alongside the sequence number
			msg_rand = Random.get_random_bytes(6)
			nonce = self.snd_num.to_bytes(length=2, byteorder='big') + msg_rand
			# Encrypt the data with the AES session key
			cipher_gcm = AES.new(self.session_key, AES.MODE_GCM, nonce =nonce, mac_len = 12)

			msg_size = self.size_msg_hdr + len(msg_payload) + 12
			msg_rand = Random.get_random_bytes(6)
			msg_hdr = self.msg_hdr_ver + msg_type + msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big') + nonce + self.msg_hdr_rsv

			cipher_gcm.update(msg_hdr)
			ciphertext, tag = cipher_gcm.encrypt_and_digest(msg_payload)
			# DEBUG 
			if self.DEBUG:
				print('MTP message to send (' + str(msg_size) + '):')
				print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
				print('BDY (' + str(len(msg_payload)) + '): ')
				print(msg_payload.hex())
				print('MAC (' + str(len(tag)) + '): ' + tag.hex())
				print('------------------------------------------')
			
			# DEBUG 
			# try to send
			try:
				self.send_bytes(msg_hdr + ciphertext + tag)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
			self.snd_num += 1

		

