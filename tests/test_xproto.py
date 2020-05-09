"""Unit tests for crypto module."""

import unittest
import xproto as x
import datetime

class AuthTest(unittest.TestCase):

    def test_auth_reg(self):
        usr = x.AgentUser()
        usr2 = x.AgentUser()
        src = x.Service()
        src2 = x.Service()
        insp = x.Inspector("паспортные данные")
        insp2 = x.Inspector("инн")

        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        x.AUTH.reg_service(src2)
        x.AUTH.reg_inspector(insp)
        x.AUTH.reg_user(usr2)
        x.AUTH.reg_inspector(insp2)

        self.assertEqual(x.AUTH.get_user(usr.ID), usr.key_pair.public)
        self.assertEqual(x.AUTH.get_service(src.ID), src.key_pair.public)
        self.assertEqual(x.AUTH.get_inspector_sig(insp.ID), insp.sign_pair.public)
        self.assertEqual(x.AUTH.get_inspector_vko(insp.ID), insp.vko_pair.public)
        self.assertEqual(x.AUTH.scope2inspector(insp.scope), insp.ID)


class MessageTest(unittest.TestCase):

    def setUp(self):

        # some random data
        scope = "паспортные данные"
        secdata = "Иванов Иван Иванович"
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)

        # REGISTRATION STEP
        usr = x.AgentUser()
        src = x.Service()
        insp = x.Inspector(scope)
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        x.AUTH.reg_inspector(insp)
        insp.add_user(usr, secdata)

        # Service -> User
        req = src.create_request(usr.ID, scope, ttl)
        # User -> Service
        blob = usr.create_blob(req, data = secdata)
        # Service -> Inspector
        reply = insp.decrypt_blob(blob, 
            key = insp.get_vko(blob))
        # Inspector -> Service
        resp = insp.verify_blob(blob)

        # data 
        self.scope = scope
        self.secdata = secdata
        self.due = due
        self.ttl = ttl

        # entities
        self.usr = usr
        self.src = src
        self.insp = insp
        self.auth = x.AUTH

        # messages
        self.req = req
        self.blob = blob
        self.reply = reply
        self.resp = resp


    def test_form_request(self):
        UID = self.usr.ID
        SrcID = self.src.ID
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        self.assertEqual(self.req.uid, UID)
        self.assertEqual(self.req.srcid, SrcID)
        self.assertEqual(self.req.scope, self.scope)
        self.assertEqual(self.req.ttl.produced, today)
        self.assertEqual(self.req.ttl.expired, due)

    def test_form_blob(self):
        self.assertEqual(self.blob.uid, self.usr.ID)

    def test_form_reply(self):
        reply = self.reply
        req = reply.request
        self.assertEqual(reply.secdata, self.secdata)
        self.assertEqual(req.uid, self.usr.ID)
        self.assertEqual(req.srcid, self.src.ID)
        self.assertEqual(req.scope, self.scope)
        self.assertEqual(req.scope, self.insp.scope)
        self.assertEqual(req.ttl.expired, self.due)

    def test_form_response(self):
        resp = self.resp
        # for good secdata the answer is 1
        self.assertEqual(resp.answer, b'1')
        #raw = insp.send_response(resp)
        #resp = src.receive_response(raw)
        # trying to give false secdata
        fakedata = "Иванов Иван Петрович"
        fakeblob = self.usr.create_blob(self.req, data = fakedata)
        resp = self.insp.verify_blob(fakeblob)
        # for fake data the answer must be 0
        self.assertEqual(resp.answer, b'0')

    def test_verifications(self):
        self.assertTrue(self.usr.check_request(self.req))
        self.assertTrue(self.src.check_blob(self.blob))
        self.assertTrue(self.insp.check_blob(self.blob))
        self.assertTrue(self.src.check_response(self.resp))




class ParserTest(unittest.TestCase):

    def setUp(self):

        # some random data
        scope = "паспортные данные"
        secdata = "Иванов Иван Иванович"
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)

        # REGISTRATION STEP
        usr = x.AgentUser()
        src = x.Service()
        insp = x.Inspector(scope)
        x.AUTH.reg_user(usr)
        x.AUTH.reg_service(src)
        x.AUTH.reg_inspector(insp)
        insp.add_user(usr, secdata)

        # Service -> User
        req = src.create_request(usr.ID, scope, ttl)
        raw = src.send_request(req)
        req2 = usr.receive_request(raw)
        # User -> Service
        blob = usr.create_blob(req, data = secdata)
        raw = usr.send_blob(blob)
        blob2 = src.receive_blob(raw)
        # Service -> Inspector
        raw = src.send_blob(blob2)
        blob3 = insp.receive_blob(raw)
        reply = insp.decrypt_blob(blob3, 
            key = insp.get_vko(blob3))
        # Inspector -> Service
        resp = insp.verify_blob(blob3)
        raw = insp.send_response(resp)
        resp2 = src.receive_response(raw)

        self.req = req
        self.req2 = req2
        self.blob = blob
        self.blob2 = blob2
        self.blob3 = blob3
        self.reply_content = reply
        self.resp = resp
        self.resp2 = resp2

        self.scope = scope
        self.secdata = secdata
        self.ttl = ttl


    def test_encode_str(self):
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

    def test_encode_request(self):
        self.assertEqual(self.req.srcid, self.req2.srcid)
        self.assertEqual(self.req.uid, self.req2.uid)
        self.assertEqual(self.req.scope, self.req2.scope)
        self.assertEqual(self.req.ttl.produced, self.req2.ttl.produced)
        self.assertEqual(self.req.ttl.expired, self.req2.ttl.expired)

    def test_encode_blob(self):
        self.assertEqual(self.blob.uid, self.blob2.uid)
        self.assertEqual(self.blob.pub, self.blob2.pub)
        self.assertEqual(self.blob.reply, self.blob2.reply)
        self.assertEqual(self.blob.uid, self.blob3.uid)
        self.assertEqual(self.blob.pub, self.blob3.pub)
        self.assertEqual(self.blob.reply, self.blob3.reply)

    def test_encode_reply(self):
        secdata = self.reply_content.secdata
        req = self.req
        self.assertEqual(secdata, self.secdata)
        self.assertEqual(req.srcid, self.req.srcid)
        self.assertEqual(req.uid, self.req.uid)
        self.assertEqual(req.scope, self.req.scope)
        self.assertEqual(req.ttl.produced, self.req.ttl.produced)
        self.assertEqual(req.ttl.expired, self.req.ttl.expired)

    def test_encode_response(self):
        self.assertEqual(self.resp.iid, self.resp2.iid)
        self.assertEqual(self.resp.blob.uid, self.resp2.blob.uid)
        self.assertEqual(self.resp.blob.pub, self.resp2.blob.pub)
        self.assertEqual(self.resp.blob.reply, self.resp2.blob.reply)
        self.assertEqual(self.resp.ttl.produced, self.resp2.ttl.produced)
        self.assertEqual(self.resp.ttl.expired, self.resp2.ttl.expired)
        self.assertEqual(self.resp.answer, self.resp2.answer)


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
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(today, due)
        req = src.create_request(usr.ID, scope, ttl)
        blob = usr.create_blob(req, data = secdata)
        reply = insp.decrypt_blob(blob, key = insp.get_vko(blob))
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