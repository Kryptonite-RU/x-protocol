from .x_utils import safe_encode, split_iv, find_date
from .crypto import vko, rand_bytes, KeyPair, CBC, Grasshopper
import xproto.crypto as crypto
from .messages import Response, ReplyContent, Blob, Request
from .auth_center import AUTH 

import datetime

class Inspector:
    def __init__(self,  scope, 
        ID=None, keys_sign=None, keys_vko=None, 
        database=None, auth=None):
        self.scope = scope
        self.ID = ID
        if keys_sign is None:
            keys_sign = KeyPair()
        if keys_vko is None:
            keys_vko = KeyPair()
        self.sign_pair = keys_sign
        self.vko_pair = keys_vko
        if database is None:
            database = {}
        self.database = database
        if auth is None:
            auth = AUTH
        self.AUTH = auth

    def add_user(self, uid, secdata, 
        date = datetime.datetime.now().date()):
        try:
            self.database[uid][date] = secdata 
        except KeyError:
            self.database[uid] = {}
            self.database[uid][date] = secdata

    def receive_blob(self, raw):
        blob = Blob.parse(raw)
        return blob

    def check_blob(self, blob):
        s = blob.sig
        UID = blob.uid
        pub = self.AUTH.get_user(UID)
        encoded = blob.content()
        return pub.verify(encoded, s)

    def receive_request(self, raw):
        req = Request.parse(raw)
        return req

    def check_request(self, req):
        SrcID = req.srcid
        pub = self.AUTH.get_service(SrcID)
        content = req.content()
        s = req.sig
        return pub.verify(content, s)

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
        reply_content = ReplyContent.parse(reply_content)
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

    def to_dict(self):
        d = {}
        d["id"] = self.ID
        d["scope"] = self.scope
        d["keys_sign"] = self.sign_pair.to_dict()
        d["keys_vko"] = self.vko_pair.to_dict()
        data = {}
        db = self.database
        for (i, uid) in enumerate(db.keys()):
            data[i] = {}
            data[i]["uid"] = uid
            data[i]["value"] = {}
            for (j, date) in enumerate(db[uid].keys()):
                data[i]["value"][j] = {}
                data[i]["value"][j]["time"] = str(date)
                data[i]["value"][j]["sec"] = db[uid][date]
        d["database"] = data
        return d

    @classmethod
    def from_dict(cls, d):
        ID = d["id"]
        scope = d["scope"]
        keys_sign = KeyPair.from_dict(d["keys_sign"])
        keys_vko = KeyPair.from_dict(d["keys_vko"])
        db = d["database"]
        data = {}
        for i in db.keys():
            uid = db[i]["uid"]
            data[uid] = {}
            for j in db[i]["value"].keys():
                rawstr = db[i]["value"][j]["time"]
                res = datetime.datetime.strptime(rawstr, '%Y-%m-%d')
                time = res.date()
                secdata = db[i]["value"][j]["sec"]
                data[uid][time] = secdata
        return cls(scope, keys_sign=keys_sign, 
            keys_vko=keys_vko, ID=ID, database=data)
