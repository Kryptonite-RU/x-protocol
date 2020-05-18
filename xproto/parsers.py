import datetime
from .messages import Request, ReplyContent, Response, Blob, TTL
from .consts import *

def cut_signature(data):
    return data[: -SIG_LENGTH]

def parse_number(raw):
    return int.from_bytes(raw, 'big')

def parse_str(raw):
    return raw.decode()

# # bytes date in YYYY-MM-DDYYYY-MM-DD format
# def parse_date(raw):
#     rawstr1 = raw.decode()[ : DATE_LENGTH]
#     rawstr2 = raw.decode()[DATE_LENGTH : ]
#     res1 = datetime.datetime.strptime(rawstr1, '%Y-%m-%d')
#     res2 = datetime.datetime.strptime(rawstr2, '%Y-%m-%d')
#     ttl = TTL(res2.date(), produced=res1.date())
#     return ttl

# def parse_request(raw):
#     sig   = raw[-SIG_LENGTH : ]
#     raw = cut_signature(raw)
#     SrcID = parse_number(raw[: ID_LENGTH])
#     UID   = parse_number(raw[ID_LENGTH : 2*ID_LENGTH])
#     ttl   = parse_date(raw[-TTL_LENGTH : ])
#     scope = parse_str(raw[2*ID_LENGTH : -TTL_LENGTH])
#     req = Request(SrcID, UID, scope, ttl, sig = sig)
#     return req

# def parse_blob(raw):
#     pub_ephem = raw[: SIG_LENGTH]
#     UID   = parse_number(raw[SIG_LENGTH : SIG_LENGTH + ID_LENGTH])
#     reply = raw[SIG_LENGTH + ID_LENGTH : ]
#     sig   = reply[-SIG_LENGTH : ]
#     reply = cut_signature(reply)
#     blob  = Blob(pub_ephem, UID, reply, sig = sig)
#     return blob

# def parse_response(raw):
#     sig = raw[-SIG_LENGTH : ]
#     raw = cut_signature(raw)
#     ans = raw[-ANS_LENGTH : ]
#     ttl = parse_date(raw[-(ANS_LENGTH + TTL_LENGTH) : -ANS_LENGTH])
#     ID = parse_number(raw[: ID_LENGTH])
#     raw = raw[ID_LENGTH : ]
#     raw_blob = raw[ : -(ANS_LENGTH + TTL_LENGTH)]
#     blob = parse_blob(raw_blob)
#     resp = Response(ID, blob, ttl, ans, sig = sig)
#     return resp

# def parse_reply(raw):
#     req_len = parse_number(raw[:REQUEST_MAXLEN])
#     raw = raw[REQUEST_MAXLEN : ]
#     req = parse_request(raw[ : req_len])
#     secdata = parse_str(raw[req_len : -SALT_LENGTH])
#     salt = raw[ -SALT_LENGTH : ]
#     return ReplyContent(req, secdata, salt = salt)

