#python3

from Crypto.Hash import SHA256
from siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_UPL_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_UPL:
    def __init__(self, mtp):

        self.DEBUG = False
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.size_fragment = 1024
        # --------- STATE ------------
        self.mtp = mtp


    # builds an upload response from a dictionary
    def build_upload_res(self, upl_res_struct):

        upl_res_str = upl_res_struct['file_hash'].hex()
        upl_res_str += self.delimiter + str(upl_res_struct['file_size'])
        return upl_res_str.encode(self.coding)


    # parses an upload response into a dictionary
    def parse_upload_res(self, upl_res):

        upl_res_fields = upl_res.decode(self.coding).split(self.delimiter)
        upl_res_struct = {}
        upl_res_struct['file_hash'] = bytes.fromhex(upl_res_fields[0])
        upl_res_struct['file_size'] = int(upl_res_fields[1])
        return upl_res_struct


    # uploads file at filepath in fragments to the server (to be used by the client)
    def handle_upload_client(self, filepath):

        # TODO: implement this function!
        file = open(filepath, "rb")
        while True:
            file_fragment = file.read(self.size_fragment)
            fragment_length = len(file_fragment)
            try:
                if fragment_length == self.size_fragment:
                    self.mtp.send_msg(self.mtp.type_upload_req_0, file_fragment)
                else:
                    self.mtp.send_msg(self.mtp.type_upload_req_1, file_fragment)
                    break
            except SiFT_MTP_Error as e:
                raise SiFT_UPL_Error('Unable to send command response --> ' + e.err_msg)

        
        file.close()
        msg_type, msg_payload = self.mtp.receive_msg()
            
        



    # handles a file upload on the server (to be used by the server)
    def handle_upload_server(self, filepath):

        # TODO: implement this function!

        file = open(filepath, 'wb')
        hash_fn = SHA256.new()
        file_length = 0
        
        while True:
            try:
                msg_type, msg_payload = self.mtp.receive_msg()
                file.write(msg_payload)
                file_length += len(msg_payload)
                hash_fn.update(msg_payload)
            except SiFT_MTP_Error as e:
                raise SiFT_UPL_Error('Unable to send upload response --> ' + e.err_msg)
            if msg_type == self.mtp.type_upload_req_1:
                file.write(msg_payload)
                file.close()
                break

        request_hash = hash_fn.digest()
        msg_payload = request_hash.hex()+ self.delimiter + str(file_length)
        self.mtp.send_msg(self.mtp.type_upload_res, msg_payload.encode(self.coding))
    
                
                
        
                
                
    
        
    







