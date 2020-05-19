import json
import xproto as x

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode("utf-8") # <- or any other encoding of your choice
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

def dict_to_json(d):
    return json.dumps(d, cls = MyEncoder)

# where entity is AgentUser/Service/Inspector
def to_json(entity):
    d = entity.to_dict()
    return dict_to_json(d)

def json_to_src(jstr):
    d = json.loads(jstr)
    return x.Service.from_dict(jd)

def json_to_usr(jstr):
    d = json.loads(jstr)
    return x.Service.from_dict(jd)

def json_to_insp(jstr):
    d = json.loads(jstr)
    return x.Inspector.from_dict(d)


def auth_to_json(auth):
    #     users = {},
    #     services = {}
    #     inspectors_sig = {}
    #     inspectors_vko = {}
    #     scopes = {},
    #     total_ids = 0
    d = {}
    d["id"] = insp.ID
    d["scope"] = insp.scope
    d["sign_private"] = insp.sign_pair.private
    d["sign_certificate"] = src.sign_pair.public.certificate
    d["vko_private"] = insp.vko_pair.private
    d["vko_certificate"] = insp.vko_pair.public.certificate
    d["database"] = insp.database
    return json.dumps(d)


def json_to_file(filename, data):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile)

def file_to_json(filename):  
    with open(filename) as json_file:
        data = json.load(json_file)
    return data

def load_src(filename):
    jstr = file_to_json(filename)
    src = json_to_src(jstr)
    return src

def load_usr(filename):
    jstr = file_to_json(filename)
    usr = json_to_usr(jstr)
    return usr

def load_insp(filename):
    jstr = file_to_json(filename)
    insp = json_to_insp(jstr)
    return insp

def save_src(filename, src):
    jstr = src_to_json(src)
    json_to_file(filename, jstr)

def save_usr(filename, usr):
    jstr = usr_to_json(usr)
    json_to_file(filename, jstr)

def save_insp(filename, insp):
    jstr = insp_to_json(insp)
    json_to_file(filename, jstr)