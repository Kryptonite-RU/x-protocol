from .x_utils import safe_encode
from .crypto import rand_bytes, KeyPair
from .messages import Request
from .auth_center import AUTH 


class Service:
    def __init__(self, keys = KeyPair()):
        self.ID = None
        self.key_pair = keys
        self.database = {}

    def check_blob(blob):
        s = blob.sig
        UID = blob.uid
        pub = AUTH.get_user(UID)
        encoded = blob.content()
        return pub.verify(encoded, s)

    def check_response(resp):
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
  