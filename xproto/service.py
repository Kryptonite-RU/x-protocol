from .x_utils import safe_encode
from .crypto import rand_bytes, KeyPair
from .messages import Request, Blob, Response
from .auth_center import AUTH 

class Service:
    def __init__(self, keys=KeyPair(), ID=None, db={}):
        self.ID = ID
        self.key_pair = keys
        self.database = db

    def receive_response(self, raw):
        return Response.parse(raw)

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
        self.database[Request] = None   # no response for this request
        return req

    def send_request(self, request):
        return request.encode()

    def send_blob(self, blob):
        return blob.encode()
  