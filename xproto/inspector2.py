from .x_utils import safe_encode, split_iv, find_date
from .parsers import parse_blob, parse_reply, parse_date
from .crypto import vko, rand_bytes, KeyPair, CBC, Grasshopper
import xproto.crypto as crypto
from .messages import Response
from .auth_center import AUTH 

import datetime

class Inspector:
    def __init__(self,  scope, 
        keys_sign = KeyPair(), 
        keys_vko = KeyPair(), 
        database={}):
        self.database = database
        self.scope = scope
        self.ID = None
        self.sign_pair = keys_sign
        self.vko_pair = keys_vko

    def add_user(self, usr, secdata, 
        date = datetime.datetime.now().date()):
        uid = usr.ID
        try:
            self.database[uid][date] = secdata 
        except KeyError:
            self.database[uid] = {}
            self.database[uid][date] = secdata

    def receive_blob(self, raw):
        blob = parse_blob(raw)
        return blob

    def check_blob(self, blob):
        s = blob.sig
        UID = blob.uid
        pub = AUTH.get_user(UID)
        encoded = blob.content()
        return pub.verify(encoded, s)

    # returns True iff time is in ttl 
    # (corresponds to the ttl value)
    def check_ttl(self, ttl, 
        curr = datetime.datetime.now().date()):
        return curr <= ttl.expired

    def check_uid(self, request, blob):
        return request.uid == blob.uid

    def check_ttl_scope(self, request):
        return self.check_ttl(request.ttl) and \
        (self.scope == request.scope)

    # check that personal data is valid
    def check_data(self, secdata, uid, ttl): 
        try:
            user_secdata = self.database[uid]
            ttl_changes = user_secdata.keys()
            key_ttl = find_date(ttl_changes, ttl.produced)
            if key_ttl:
                valid_data = user_secdata[key_ttl]
            else:
                return b'0'
            if secdata == valid_data:
                return b'1'
            else:
                return b'0'
        except KeyError:
            return b'0'


    def get_vko(self, blob):
        key2 = crypto.export_public_key(blob.pub)
        #key2 = blob.pub
        return vko(self.vko_pair, key2)

    def decrypt_blob(self, blob, key = None):
        cipher = Grasshopper(key)
        cbc = CBC(cipher)
        iv, reply = split_iv(blob.reply, mode = cbc)
        cbc.set_iv(iv)
        reply_content = cbc.decrypt(reply)
        reply_content = parse_reply(reply_content)
        return reply_content

    def verify_blob(self, blob): 
        if not self.check_blob(blob):
            raise Exception
        reply = self.decrypt_blob(blob, key = self.get_vko(blob)) 
        request = reply.request
        secdata = reply.secdata
        if not self.check_uid(request, blob):
            raise Exception
        if not self.check_ttl_scope(request):
            raise Exception
        answer = self.check_data(secdata, blob.uid, request.ttl)
        response = Response(self.ID, blob, request.ttl, answer, 
            key_pair = self.sign_pair)
        return response

    def send_response(self, resp):
        return resp.encode()
