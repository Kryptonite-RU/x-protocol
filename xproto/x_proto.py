# from service import Service
# from auth_center import AUTH
# from user import AgentUser
# from inspector2 import Inspector
# from messages import Request, Response, ReplyContent, Blob
# from parsers import parse_request, parse_blob, parse_response
# import datetime

usr = AgentUser()
src = Service()
insp = Inspector("паспортные данные")

AUTH.reg_user(usr)
AUTH.reg_service(src)
AUTH.reg_inspector(insp)

# create request for user
UID = usr.ID
scope = "паспортные данные"
due = datetime.date(2020, 5, 10)
req = src.create_request(UID, scope, due)
# encode and send
raw_request = src.send_request(req)

# receive and decode request
req2 = usr.receive_request(raw_request)
# check request and form blob
blob = usr.create_blob(req2)
raw_blob = usr.send_blob(blob)

blob = insp.receive_blob(raw_blob)
resp = insp.verify_blob(blob)
