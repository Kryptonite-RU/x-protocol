from x_utils import safe_encode, parse_blob, check_ttl
from vko import vko
from utils import rand_bytes
from signature import KeyPair
from modes import CBC
from grasshopper import Grasshopper
import datetime

class Response:
    def __init__(self, blob, ttl, answer, key_pair):
        self.blob = blob.encode()
        self.ttl = safe_encode(ttl),
        self.answer = safe_encode(answer)
        content = self.blob + self.ttl + self.answer
        self.sig = key_pair.sign(content)

    def encode(self):
        return self.blob + self.ttl + self.answer

class Inspector:
    def __init__(self,  address, auth_center, scope, keys_sign=None, keys_vko=None, database={}):
        self.__database = database
        self.scope = scope
        self.address = safe_encode(address)
        self.IID = auth_center.inspector_register_init(address, scope)
        if keys_sign:
            self.sign_pair = keys_sign
        else:
            raw_key = rand_bytes(32)
            self.__key_sign_pair = KeyPair(raw_key)
        if keys_vko:
            self.__key_vko_pair = keys_vko
        else:
            raw_key = rand_bytes(32)
            self.__key_vko_pair = KeyPair(raw_key)
        self.__certificate = auth_center.inspector_register_cert(self.__key_sign_pair, self.__key_vko_pair)

    def __verify_signature(self, blob):
        s = blob.sig
        UID = blob.uid
        pub = get_public_key(UID) # Currently not working
        encoded = blob.encode()
        return pub.verify(encoded, s)

    def __get_vko(self, blob):
        return vko(self.__key_vko_pair, blob.pub)

    def __decrypt_blob(self, blob, key):
        iv, reply = parse_blob(blob) # Currently not working
        cipher = Grasshopper(key)
        cbc = CBC(cipher)
        cbc.set_iv(iv)
        reply_content = cbc.decrypt(reply)
        return reply_content

    def __check_user_id(self, request, blob):
        return request.uid == blob.uid

    def __check_ttl_scope_service(self, ttl, scope, srcid, time):
        return check_ttl(ttl, time) and self.scope == scope and srcid == srcid

    def __data_validate(self, secdata, uid, ttl): # function for personal data validation
        return "yes"

    def blob_verify(self, blob, srcid):                                   # Requested validation. Step 1
        time = datetime.datetime.now()
        if not self.__verify_signature(blob):
            raise Exception                                                                     # Step 2
        try:
            key = self.__get_vko(blob)                                                          # Step 3
            request, secdata, salt = self.__decrypt_blob(blob, key)                             # Step 4
        except Exception:
            raise
        if not self.__check_user_id(request, blob):                                             # Step 5
            raise Exception
        if not self.__check_ttl_scope_service(request.ttl, request.scope, srcid, time):         # Step 6
            raise Exception
        answer = self.__data_validate(secdata, blob.uid, request.ttl)                           # Step 7
        response = Response(blob, request.ttl, answer, self.__key_sign_pair)                    # Step 8
        return response
