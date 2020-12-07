#import pickle
import xproto as x
import json
from xproto.x_utils import dict_utf, utf_dict 
from xproto.errors import UsrLoadError, SrcLoadError, InspLoadError,AuthLoadError

def dict_to_file(dict, file):
    with open(file, "w") as f:
        res = dict_utf(dict)
        json.dump(res, f, indent=4)
        #pickle.dump(dict, f)

def file_to_dict(file):
    with open(file, "r") as f:
        json_res = json.load(f)
        res = utf_dict(json_res)
        return res

def load_src(filename):
    d = file_to_dict(filename)
    try:
        src = x.Service.from_dict(d)
    except:
        raise SrcLoadError from None
    return src

def load_usr(filename):
    d = file_to_dict(filename)
    try:
        usr = x.AgentUser.from_dict(d)
    except:
        raise UsrLoadError from None
    return usr

def load_insp(filename):
    d = file_to_dict(filename)
    try:
        insp = x.Inspector.from_dict(d)
    except:
        raise InspLoadError from None
    return insp

def load_auth(filename):
    d = file_to_dict(filename)
    try:
        auth = x.AuthCenter.from_dict(d)
    except:
        raise AuthLoadError from None
    return auth

def to_file(filename, entity):
    d = entity.to_dict()
    dict_to_file(d, filename)
