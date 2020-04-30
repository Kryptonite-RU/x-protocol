import datetime
from .messages import Request, ReplyContent, Response, Blob
from .consts import *

def cut_signature(data):
    return data[: -SIG_LENGTH]

def parse_request(raw):
    sig   = raw[-SIG_LENGTH : ]
    raw = cut_signature(raw)
    SrcID = raw[: ID_LENGTH]
    UID   = raw[ID_LENGTH : 2*ID_LENGTH]
    ttl   = raw[-TTL_LENGTH : ]
    scope = raw[2*ID_LENGTH : -TTL_LENGTH]
    req = Request(SrcID, UID, scope, ttl, sig = sig)
    return req

def parse_blob(raw):
    pub_ephem = raw[: SIG_LENGTH]
    UID = raw[SIG_LENGTH : SIG_LENGTH + ID_LENGTH]
    reply = raw[SIG_LENGTH + ID_LENGTH : ]
    sig = reply[-SIG_LENGTH : ]
    reply = cut_signature(reply)
    blob = Blob(pub_ephem, UID, reply, sig = sig)
    return blob

def parse_response(raw):
    sig   = raw[-SIG_LENGTH : ]
    raw = cut_signature(raw)
    ans = raw[-ANS_LENGTH : ]
    ttl = raw[-(ANS_LENGTH + TTL_LENGTH) : -ANS_LENGTH]
    ID = raw[: ID_LENGTH]
    raw = raw[ID_LENGTH : ]
    raw_blob = raw[ : -(ANS_LENGTH + TTL_LENGTH)]
    blob = parse_blob(raw_blob)
    resp = Response(ID, blob, ttl, ans, sig = sig)
    return resp

def parse_reply(raw):
    req_len = int.from_bytes(raw[:REQUEST_MAXLEN], 'big')
    raw = raw[REQUEST_MAXLEN : ]
    req = parse_request(raw[ : req_len])
    secdata = raw[req_len : -SALT_LENGTH]
    salt = raw[ -SALT_LENGTH : ]
    return ReplyContent(req, secdata, salt = salt)

# bytes date in YYYY-MM-DD format
def parse_date(raw):
    rawstr = raw.decode()
    res = datetime.datetime.strptime(rawstr, '%Y-%m-%d')
    return res.date()
