import json
import xproto as x

def src_to_json(src):
    d = {}
    d["id"] = src.ID
    d["private"] = src.key_pair.private
    d["certificate"] = src.key_pair.public.certificate
    d["database"] = src.database
    return json.dumps(d)

def json_to_src(jstr):
    jd = json.loads(jstr)
    srcid = jd["id"]
    kpair = x.crypto.KeyPair(private=jd["private"],
        cert = jd["certificate"])
    db = jd["database"]
    return x.Service(ID=srcid, keys=kpair, db=db)

def usr_to_json(usr):
    # all fields are the same!!
    return src_to_json(usr)

def json_to_usr(jstr):
    jd = json.loads(jstr)
    uid = jd["id"]
    kpair = x.crypto.KeyPair(private=jd["private"],
        cert = jd["certificate"])
    db = jd["database"]
    return x.AgentUser(ID=srcid, keys=kpair, db=db)

def insp_to_json(insp):
    d = {}
    d["id"] = insp.ID
    d["scope"] = insp.scope
    d["sign_private"] = insp.sign_pair.private
    d["sign_certificate"] = src.sign_pair.public.certificate
    d["vko_private"] = insp.vko_pair.private
    d["vko_certificate"] = insp.vko_pair.public.certificate
    d["database"] = insp.database
    return json.dumps(d)


def json_to_insp(jstr):
    jd = json.loads(jstr)
    iid = jd["id"]
    sign_pair = x.crypto.KeyPair(private=jd["sign_private"],
        cert = jd["sign_certificate"])
    vko_pair = x.crypto.KeyPair(private=jd["vko_private"],
        cert = jd["vko_certificate"])
    db = jd["database"]
    return x.Inspector(ID=iid, vko_keys=vko_pair, 
        sign_keys = sign_pair, database=db)


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