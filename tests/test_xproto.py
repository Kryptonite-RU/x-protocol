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

    def test_encode_scope(self):
        scope = "паспортные данные"
        raw = x.x_utils.safe_encode(scope)
        scope2 = x.parsers.parse_str(raw)
        self.assertEqual(scope, scope2)

    def test_encode_int(self):
        s = (42).to_bytes(10, 'big')
        n = int.from_bytes(s, 'big')
        self.assertEqual(n, 42)

    def test_encode_id(self):
        ID = 123
        s = x.x_utils.encode_id(ID)
        ID2 = x.parsers.parse_number(s)
        self.assertEqual(ID, ID2)

    def test_encode_date(self):
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)
        raw = x.x_utils.safe_encode(ttl)
        ttl2 = x.parsers.parse_date(raw)
        self.assertEqual(ttl.produced, ttl2.produced)
        self.assertEqual(ttl.expired, ttl2.expired)

    def test_form_request(self):
        usr = x.AgentUser()
        src = x.Service()
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        # create request for user
        UID = usr.ID
        SrcID = src.ID
        scope = "паспортные данные"
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)
        req = src.create_request(UID, scope, ttl)
        self.assertEqual(req.uid, UID)
        self.assertEqual(req.srcid, SrcID)
        self.assertEqual(req.scope, scope)
        self.assertEqual(req.ttl.produced, today)
        self.assertEqual(req.ttl.expired, due)

    def test_encode_request(self):
        usr = x.AgentUser()
        src = x.Service()
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        # create request for user
        UID = usr.ID
        scope = "паспортные данные"
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)
        req = src.create_request(UID, scope, ttl)
        # encode and send
        raw_request = src.send_request(req)
        # receive and decode request
        req2 = usr.receive_request(raw_request)
        self.assertEqual(req.srcid, req2.srcid)
        self.assertEqual(req.uid, req2.uid)
        self.assertEqual(req.scope, req2.scope)
        self.assertEqual(req.ttl.produced, req2.ttl.produced)
        self.assertEqual(req.ttl.expired, req2.ttl.expired)

    def test_blob_create(self):
        usr = x.AgentUser()
        src = x.Service()
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        # create request for user
        UID = usr.ID
        scope = "паспортные данные"
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)
        req = src.create_request(UID, scope, ttl)
        # encode and send
        raw_request = src.send_request(req)
        # receive and decode request
        req2 = usr.receive_request(raw_request)
        # check request and form blob
        secdata = "Иванов Иван Иванович"
        blob = usr.create_blob(req2, data = secdata)
        self.assertEqual(blob.uid, usr.ID)
        self.assertTrue(src.check_blob(blob))


    def test_encode_blob(self):
        scope = "паспортные данные"
        secdata = "Иванов Иван Иванович"

        # REGISTRATION STEP
        usr = x.AgentUser()
        src = x.Service()
        insp = x.Inspector(scope)
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        x.AUTH.reg_inspector(insp)
        insp.add_user(usr, secdata)

        # create request for user and send
        UID = usr.ID
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)
        req = src.create_request(UID, scope, ttl)

        blob = usr.create_blob(req, data = secdata)   
        raw = src.send_blob(blob)
        blob2 = insp.receive_blob(raw)

        self.assertEqual(blob.uid, blob2.uid)
        self.assertEqual(blob.pub, blob2.pub)
        self.assertEqual(blob.reply, blob2.reply)


    def test_proto(self):
        scope = "паспортные данные"
        secdata = "Иванов Иван Иванович"

        # REGISTRATION STEP
        usr = x.AgentUser()
        src = x.Service()
        insp = x.Inspector(scope)
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        x.AUTH.reg_inspector(insp)
        insp.add_user(usr, secdata)

        # create request for user and send
        UID = usr.ID
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)
        req = src.create_request(UID, scope, ttl)
        # create blob for the request
        blob = usr.create_blob(req, data = secdata)
        # src checks request and send to inspector
        self.assertTrue(src.check_blob(blob))
        # inspector gets blob and checks  
        # everything it has to check
        reply = insp.decrypt_blob(blob, key = insp.get_vko(blob))
        req = reply.request
        self.assertEqual(reply.secdata, secdata)
        self.assertEqual(req.uid, usr.ID)
        self.assertEqual(req.srcid, src.ID)
        self.assertEqual(req.scope, scope)
        self.assertEqual(req.scope, insp.scope)
        self.assertEqual(req.ttl.expired, due)
        resp = insp.verify_blob(blob)
        # for good secdata the answer is 1
        self.assertEqual(resp.answer, b'1')
        raw = insp.send_response(resp)

        resp = src.receive_response(raw)
        self.assertTrue(src.check_response(resp))

        # trying to give false secdata
        secdata = "Иванов Иван Петрович"
        blob = usr.create_blob(req, data = secdata)
        resp = insp.verify_blob(blob)
        # for bad secdata the answer is 1
        self.assertEqual(resp.answer, b'0')



if __name__ == "__main__":
    unittest.main()