"""Unit tests for crypto module."""

import unittest
import xproto as x
import datetime
# import sys
# from io import StringIO

class AuthTest(unittest.TestCase):

    def test_auth_reg(self):
        usr = x.AgentUser()
        src = x.Service()
        insp = x.Inspector("паспортные данные")

        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        x.AUTH.reg_inspector(insp)

        self.assertEqual(x.AUTH.get_user(usr.ID), usr.key_pair.public)
        self.assertEqual(x.AUTH.get_service(src.ID), src.key_pair.public)
        self.assertEqual(x.AUTH.get_inspector_sig(insp.ID), insp.sign_pair.public)
        self.assertEqual(x.AUTH.get_inspector_vko(insp.ID), insp.vko_pair.public)
        self.assertEqual(x.AUTH.scope2inspector(insp.scope), insp.ID)


class ParserTest(unittest.TestCase):

    def test_date_parse(self):
        due = datetime.date(2020, 5, 10)
        raw = x.x_utils.safe_encode(due)
        due2 = x.parsers.parse_date(raw)
        self.assertEqual(due, due2)

    def test_request_parse(self):
        usr = x.AgentUser()
        src = x.Service()
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        # create request for user
        UID = usr.ID
        scope = "паспортные данные"
        due = datetime.date(2020, 5, 10)
        req = src.create_request(UID, scope, due)
        # encode and send
        raw_request = src.send_request(req)
        # receive and decode request
        req2 = usr.receive_request(raw_request)
        self.assertEqual(req.srcid, req2.srcid)
        self.assertEqual(req.uid, req2.uid)
        self.assertEqual(req.scope, req2.scope)
        self.assertEqual(req.ttl, req2.ttl)

    def test_encode_decode(self):
        scope = "паспортные данные"
        scope2 = x.x_utils.safe_encode(scope).decode()
        s = (42).to_bytes(10, 'big')
        n = int.from_bytes(s, 'big')
        self.assertEqual(scope, scope2)
        self.assertEqual(n, 42)

    def test_blob_create(self):
        usr = x.AgentUser()
        src = x.Service()
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
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
        secdata = "Иванов Иван Иванович"
        blob = usr.create_blob(req2, data = secdata)
        self.assertEqual(blob.uid, usr.ID)

    def test_proto(self):
        scope = "паспортные данные"
        secdata = "Иванов Иван Иванович"
        usr = x.AgentUser()
        src = x.Service()
        insp = x.Inspector(scope)
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        x.AUTH.reg_inspector(insp)
        insp.add_user(usr, secdata)
        # create request for user and send
        UID = usr.ID
        due = datetime.date(2020, 5, 10)
        req = src.create_request(UID, scope, due)
        raw_request = src.send_request(req)
        # create blob for the request
        req2 = usr.receive_request(raw_request)
        blob = usr.create_blob(req2, data = secdata)
        raw_blob = usr.send_blob(blob)
        blob2 = insp.receive_blob(raw_blob)
        self.assertEqual(blob.uid, blob2.uid)
        self.assertEqual(blob.pub, blob2.pub)
        self.assertEqual(blob.reply, blob2.reply)
        reply = insp.decrypt_blob(blob2, key = insp.get_vko(blob))
        req = reply.request
        self.assertEqual(reply.secdata.decode(), secdata)
        self.assertEqual(req.uid, usr.ID)
        self.assertEqual(req.srcid, src.ID)
        self.assertEqual(req.scope.decode(), scope)
        self.assertEqual(req.scope, insp.scope)
        self.assertEqual(x.parsers.parse_date(req.ttl), due)
        resp = insp.verify_blob(blob2)
        # for good secdata the answer is 1
        self.assertEqual(resp.answer, b'1')

        # trying to give false secdata
        secdata = "Иванов Иван Петрович"
        blob = usr.create_blob(req2, data = secdata)
        resp = insp.verify_blob(blob)
        # for bad secdata the answer is 1
        self.assertEqual(resp.answer, b'0')







if __name__ == "__main__":
    unittest.main()