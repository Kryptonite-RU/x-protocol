from .x_utils import safe_encode
from .crypto import rand_bytes, KeyPair
from .messages import Request, Blob, Response
from .auth_center import AUTH 

def safe_to_dict(obj):
    if obj == None:
        return None
    else:
        return obj.to_dict()


class Service:
    def __init__(self, keys=KeyPair(), ID=None, db={}):
        self.ID = ID
        self.key_pair = keys
        self.database = db

    def receive_response(self, raw):
        resp = Response.parse(raw)
        return resp

    def receive_blob(self, raw):
        return Blob.parse(raw)

    def check_blob(self, blob):
        s = blob.sig
        UID = blob.uid
        pub = AUTH.get_user(UID)
        encoded = blob.content()
        return pub.verify(encoded, s)

    def check_response(self, resp):
        s = resp.sig
        IID = resp.iid    # Inspector ID
        pub = AUTH.get_inspector_sig(IID)
        encoded = resp.content()
        # check that signature is valid
        ch1 = pub.verify(encoded, s)
        # other checks ?? yes/no, ttl? blob?
        ch2 = (resp.answer == b'1')
        return (ch1 and ch2) 

    def create_request(self, UID, scope, ttl):
        req = Request(self.ID, UID, scope, ttl, 
            key_pair = self.key_pair)
        self.database[req] = None   # no response for this request
        return req

    def send_request(self, request):
        return request.encode()

    def send_blob(self, blob):
        return blob.encode()

    def to_dict(self):
        d = {}
        d["id"] = self.ID
        d["key"] = self.key_pair.to_dict()
        data = {}
        db = self.database
        for (i,key) in enumerate(db.keys()):
            data[i] = {}
            data[i]["key"] = key.to_dict()
            val = db[key]
            if val == None:
                data[i]["value"] = None
            else:
                data[i]["value"] = val.to_dict()
        d["database"] = data
        return d

    @classmethod
    def from_dict(cls, d):
        ID = d["id"]
        keys = KeyPair.from_dict(d["key"])
        db = d["database"]
        data = {}
        for i in db.keys():
            req = Request.from_dict(db[i]["key"])
            #blob = Blob.from_dict(db[i]["value"])
            val = db[i]["value"]
            if val == None:
                resp = None
            else:
                resp = Response.from_dict(val)
            data[req] = resp
        return cls(keys=keys, ID=ID, db=data)
  