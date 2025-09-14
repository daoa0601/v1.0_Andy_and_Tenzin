#python3

from Crypto.Hash import SHA256
from siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_DNL_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_DNL:
    def __init__(self, mtp):

        self.DEBUG = False
        # --------- CONSTANTS ------------
        self.size_fragment = 1024
        self.coding = 'utf-8'
        self.ready = 'Ready'
        self.cancel = 'Cancel'
        # --------- STATE ------------
        self.mtp = mtp


    # cancels file download by the client (to be used by the client)
    def cancel_download_client(self):
        self.mtp.send_msg(self.mtp.type_dnload_req, self.cancel.encode(self.coding))

    # handles file download at the client (to be used by the client)
    def handle_download_client(self, filepath):
        file = open(filepath, 'wb')
        
        self.mtp.send_msg(self.mtp.type_dnload_req, self.ready.encode(self.coding))
        print("------------------------------------------------------------------------------")
        while True:    
            try:
                msg_type, msg_payload = self.mtp.receive_msg()
                file.write(msg_payload)
            except SiFT_MTP_Error as e:
                raise SiFT_DNL_Error('Unable to send download response --> ' + e.err_msg)
            if msg_type == self.mtp.type_dnload_res_1:
                    file.write(msg_payload)
                    file.close()
                    break
        
        with open(filepath, 'rb') as f:
                hash_fn = SHA256.new()
                file_size = 0
                byte_count = 1024
                while byte_count == 1024:
                    chunk = f.read(1024)
                    byte_count = len(chunk)
                    file_size += byte_count
                    hash_fn.update(chunk)
                file_hash = hash_fn.digest()

        return file_hash

    # handles a file download on the server (to be used by the server)
    def handle_download_server(self, filepath):
        file = open(filepath, 'rb')

        msg_type, msg_payload = self.mtp.receive_msg()
        while True:
            try:
                file_fragment = file.read(self.size_fragment)
                fragment_length = len(file_fragment)
                if msg_payload.decode(self.coding) == self.ready:
                    if fragment_length == self.size_fragment:
                        self.mtp.send_msg(self.mtp.type_dnload_res_0, file_fragment)
                    else:
                        self.mtp.send_msg(self.mtp.type_dnload_res_1, file_fragment)
                        break
            except SiFT_MTP_Error as e:
                raise SiFT_DNL_Error('Unable to send download response --> ' + e.err_msg)
        file.close()



