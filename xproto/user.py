from .crypto import rand_bytes, KeyPair, vko
from .messages import ReplyContent, Blob, Request
from .auth_center import AUTH 

class AgentUser:
    def __init__(self, keys=KeyPair(), ID=None, db={}):
        self.ID = ID
        self.key_pair = keys
        # request -> blob
        self.database = db

    def receive_request(self, raw):
        req = Request.parse(raw)
        return req

    def check_request(self, req):
        SrcID = req.srcid
        pub = AUTH.get_service(SrcID)
        content = req.content()
        s = req.sig
        return pub.verify(content, s)

    def get_secdata(self, request):
        print("You are going to give sec data to the following request")
        print("Service ID: ", request.srcid)
        print("scope : ", request.scope)
        ttl = request.ttl
        print("produced: ", ttl.produced)
        print("will expire :", ttl.expired)
        secdata = input("provide your personal data: ")
        return secdata        

    def create_blob(self, request, data = None):
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
        if data == None:
            data = self.get_secdata(request)
        reply_content = ReplyContent(request, data)
        reply = reply_content.encrypt(vko_key)
        blob = Blob(ephem_keys.public, self.ID, reply, 
            key_pair = self.key_pair)
        self.database[request] = blob
        return blob

    def send_blob(self, blob):
        return blob.encode()

    def to_dict(self):
        d = {}
        d["id"] = self.ID
        d["key"] = self.key_pair.to_dict()
        data = {}
        d["database"] = data
        db = self.database
        for (i,key) in enumerate(db.keys()):
            data[i] = {}
            data[i]["key"] = key.to_dict()
            data[i]["value"] = db[key].to_dict()
        return d

    @classmethod
    def from_dict(cls, d):
        ID = d["id"]
        keys = KeyPair.from_dict(d["key"])
        db = d["database"]
        data = {}
        for i in db.keys():
            req = Request.from_dict(db[i]["key"])
            blob = Blob.from_dict(db[i]["value"])
            data[req] = blob
        return AgentUser(keys=keys, ID=ID, db=data)

        


    
