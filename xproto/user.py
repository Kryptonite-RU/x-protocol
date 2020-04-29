from .crypto import rand_bytes, KeyPair, vko
from .messages import ReplyContent, Blob
from .parsers import parse_request
from .auth_center import AUTH 

class AgentUser:
    def __init__(self, keys = KeyPair()):
        self.ID = None
        self.key_pair = keys
        self.database = {}

    def receive_request(self, raw):
        req = parse_request(raw)
        return req

    def check_request(self, req):
        SrcID = req.srcid
        pub = AUTH.get_service(SrcID)
        content = req.content()
        s = req.sig
        return pub.verify(content, s)

    def get_secdata(self, request):
        print("You are going to give sec data to the following request")
        print("Service ID: ", int.from_bytes(request.srcid, 'big'))
        print("scope : ", request.scope.decode())
        print("ttl : ", request.ttl.decode())
        secdata = input("provide your personal data: ")
        return secdata        

    def create_blob(self, request):
        if not self.check_request(request):
            raise Exception
        # get scope from request and find inspector who should
        # check the personal data
        scope = request.scope
        iid = AUTH.scope2inspector(scope)
        inspector_pub = AUTH.get_inspector_vko(iid)

        # create ephemeral key and run VKO
        ephem_keys = KeyPair()
        vko_key = vko(ephem_keys, inspector_pub)

        # create reply content: Request + SecData + salt
        secdata = self.get_secdata(request)
        reply_content = ReplyContent(request, secdata)
        raw_reply = reply_content.encrypt(vko_key)
        blob = Blob(ephem_keys.public, self.ID, raw_reply, 
            key_pair = self.key_pair)
        return blob

    def send_blob(self, blob):
        return blob.encode()


    