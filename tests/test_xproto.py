"""Unit tests for crypto module."""

import unittest
import xproto as x
import datetime
#from xproto import json_utils as jutils

class AuthTest(unittest.TestCase):

    def test_auth_reg(self):
        AUTH = x.AuthCenter()
        usr = x.AgentUser()
        usr2 = x.AgentUser()
        src = x.Service()
        src2 = x.Service()
        insp = x.Inspector("паспортные данные")
        insp2 = x.Inspector("инн")

        AUTH.reg_user(usr)
        AUTH.reg_service(src)
        AUTH.reg_service(src2)
        AUTH.reg_inspector(insp)
        AUTH.reg_user(usr2)
        AUTH.reg_inspector(insp2)

        self.assertEqual(AUTH.get_user(usr.ID), usr.key_pair.public)
        self.assertEqual(AUTH.get_service(src.ID), src.key_pair.public)
        self.assertEqual(AUTH.get_inspector_sig(insp.ID), insp.sign_pair.public)
        self.assertEqual(AUTH.get_inspector_vko(insp.ID), insp.vko_pair.public)
        self.assertEqual(AUTH.scope2inspector(insp.scope), insp.ID)


class MessageTest(unittest.TestCase):

    def setUp(self):
        
        # some random data
        scope = "паспортные данные"
        secdata = "Иванов Иван Иванович"
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(due)

        # REGISTRATION STEP
        AUTH = x.AuthCenter()
        usr = x.AgentUser(auth=AUTH)
        src = x.Service(auth=AUTH)
        insp = x.Inspector(scope, auth=AUTH)
        AUTH.reg_user(usr)
        AUTH.reg_service(src)
        AUTH.reg_inspector(insp)
        insp.add_user(usr.ID, secdata)

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
        self.auth = AUTH

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
        # trying to give false secdata
        fakedata = "Иванов Иван Петрович"
        fakeblob = self.usr.create_blob(self.req, data = fakedata)
        resp = self.insp.verify_blob(fakeblob)
        # for fake data the answer must be 0
        self.assertEqual(resp.answer, b'0')

    def test_form_old_data(self):
        scope = "паспортные данные3"
        old_data = "Иванов Иван Иванович"
        old_time = datetime.date(1990, 1, 1)
        # then the user changed his surname
        new_data = "Петров Иван Иванович"
        new_time = datetime.date(2010, 1, 1)

        # REGISTRATION STEP
        AUTH = x.AuthCenter()
        usr = x.AgentUser(auth=AUTH)
        src = x.Service(auth=AUTH)
        insp = x.Inspector(scope, auth=AUTH)
        AUTH.reg_user(usr)
        AUTH.reg_service(src)
        AUTH.reg_inspector(insp)
        insp.add_user(usr.ID, old_data, date = old_time)
        insp.add_user(usr.ID, new_data, date = new_time)

        # create request for user and send
        today = datetime.date(2020, 1, 1)
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(due, produced=today)
        req = src.create_request(usr.ID, scope, ttl)
        # first we try to verify old data
        blob = usr.create_blob(req, data = old_data)
        reply = insp.decrypt_blob(blob, key = insp.get_vko(blob))
        resp = insp.verify_blob(blob)
        # for old secdata the answer is 0
        self.assertEqual(resp.answer, b'0')
        self.assertFalse(src.check_response(resp))

        # now we try to verify NEW data
        blob = usr.create_blob(req, data = new_data)
        reply = insp.decrypt_blob(blob, key = insp.get_vko(blob))
        resp = insp.verify_blob(blob)
        # for new secdata the answer is 1
        self.assertEqual(resp.answer, b'1')
        self.assertTrue(src.check_response(resp))

        # old data for OLD blob should be 1!
        today = datetime.date(1999, 1, 1)
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(due, produced=today)
        req = src.create_request(usr.ID, scope, ttl)
        # try to verify old data
        blob = usr.create_blob(req, data = old_data)
        reply = insp.decrypt_blob(blob, key = insp.get_vko(blob))
        resp = insp.verify_blob(blob)
        # for old secdata the answer is 1, 
        # because blob is also old
        self.assertEqual(resp.answer, b'1')
        self.assertTrue(src.check_response(resp))



    def test_verifications(self):
        self.assertTrue(self.usr.check_request(self.req))
        self.assertTrue(self.src.check_blob(self.blob))
        self.assertTrue(self.insp.check_blob(self.blob))
        self.assertTrue(self.src.check_response(self.resp))




class ParserTest(unittest.TestCase):

    def setUp(self):

        # some random data
        scope = "паспортные данные4"
        secdata = "Иванов Иван Иванович"
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(due)

        # REGISTRATION STEP
        AUTH = x.AuthCenter()
        usr = x.AgentUser(auth=AUTH)
        src = x.Service(auth=AUTH)
        insp = x.Inspector(scope, auth=AUTH)
        AUTH.reg_user(usr)
        AUTH.reg_service(src)
        AUTH.reg_inspector(insp)
        insp.add_user(usr.ID, secdata)

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
        scope2 = x.x_utils.parse_str(raw)
        self.assertEqual(scope, scope2)

    def test_encode_int(self):
        s = (42).to_bytes(10, 'big')
        n = int.from_bytes(s, 'big')
        self.assertEqual(n, 42)

    def test_encode_id(self):
        ID = 123
        s = x.x_utils.encode_id(ID)
        ID2 = x.x_utils.parse_number(s)
        self.assertEqual(ID, ID2)

    def test_encode_date(self):
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(due)
        raw = x.x_utils.safe_encode(ttl)
        ttl2 = x.TTL.parse(raw)
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
        self.assertEqual(self.resp, self.resp2)


class IOTest(unittest.TestCase):

    def setUp(self):

        # some random data
        scope = "паспортные данные5"
        secdata = "Иванов Иван Иванович"
        today = datetime.datetime.today().date()
        due = datetime.date(2099, 5, 10)
        ttl = x.TTL(due)

        # REGISTRATION STEP
        AUTH = x.AuthCenter()
        usr = x.AgentUser(auth=AUTH)
        src = x.Service(auth=AUTH)
        insp = x.Inspector(scope, auth=AUTH)
        AUTH.reg_user(usr)
        AUTH.reg_service(src)
        AUTH.reg_inspector(insp)
        insp.add_user(usr.ID, secdata)

        # Service -> User
        req = src.create_request(usr.ID, scope, ttl)
        # User -> Service
        blob = usr.create_blob(req, data=secdata)
        # Inspector -> Service
        reply = insp.decrypt_blob(blob, key=insp.get_vko(blob))
        resp = insp.verify_blob(blob)

        self.req = req
        self.blob = blob
        self.reply_content = reply
        self.resp = resp

        self.usr = usr
        self.src = src
        self.insp = insp
        self.auth = AUTH


    def test_dict_request(self):
        req = self.req
        d = req.to_dict()
        req2 = x.Request.from_dict(d)
        self.assertEqual(req, req2)

    def test_dict_blob(self):
        d = self.blob.to_dict()
        self.blob2 = x.Blob.from_dict(d)
        self.assertEqual(self.blob, self.blob2)

    # def test_dict_reply(self):
    #     reply1 = self.reply_content
    #     req = reply1.request
    #     d = reply1.to_dict()
    #     reply2 = x.ReplyContent.from_dict(d)
    #     req2 = reply2.request
    #     self.assertEqual(reply1.secdata, reply2.secdata)
    #     self.assertEqual(reply1.salt, reply2.salt)
    #     self.assertEqual(req.srcid, req2.srcid)
    #     self.assertEqual(req.uid, req2.uid)
    #     self.assertEqual(req.scope, req2.scope)
    #     self.assertEqual(req.ttl.produced, req2.ttl.produced)
    #     self.assertEqual(req.ttl.expired, req2.ttl.expired)

    def test_dict_response(self):
        d = self.resp.to_dict()
        resp2 = x.Response.from_dict(d)
        self.assertEqual(self.resp, resp2)


    def test_dict_user(self):
        usr = self.usr
        d = usr.to_dict()
        usr2 = x.AgentUser.from_dict(d)
        self.assertEqual(usr.ID, usr2.ID)
        keys1 = usr.key_pair
        keys2 = usr2.key_pair
        self.assertEqual(keys1, keys2)
        for k in usr.database.keys():
            self.assertEqual(usr.database[k], usr2.database[k])
        for k in usr2.database.keys():
            self.assertEqual(usr.database[k], usr2.database[k])

    def test_dict_service(self):
        src = self.src
        d = src.to_dict()
        src2 = x.Service.from_dict(d)
        self.assertEqual(src.ID, src2.ID)
        keys1 = src.key_pair
        keys2 = src2.key_pair
        self.assertEqual(keys1, keys2)
        for k in src.database.keys():
            self.assertEqual(src.database[k], src2.database[k])
        for k in src2.database.keys():
            self.assertEqual(src.database[k], src2.database[k])

    def test_dict_insp(self):
        insp = self.insp
        d = insp.to_dict()
        insp2 = x.Inspector.from_dict(d)
        self.assertEqual(insp.ID, insp2.ID)
        self.assertEqual(insp.scope, insp2.scope)
        self.assertEqual(insp.vko_pair, insp2.vko_pair)
        self.assertEqual(insp.sign_pair, insp2.sign_pair)
        for k in insp.database.keys():
            self.assertEqual(insp.database[k], insp2.database[k])
        for k in insp2.database.keys():
            self.assertEqual(insp.database[k], insp2.database[k])

    def test_dict_auth(self):
        auth = self.auth 
        d = auth.to_dict()
        auth2 = x.AuthCenter.from_dict(d)
        self.assertEqual(auth.total_ids, auth2.total_ids)
        self.assertEqual(auth.users, auth2.users)
        self.assertEqual(auth.id_scope, auth2.id_scope)
        self.assertEqual(auth.services, auth2.services)
        self.assertEqual(auth.inspectors_sig, auth2.inspectors_sig)
        self.assertEqual(auth.inspectors_vko, auth2.inspectors_vko)

    def test_entity_io(self):
        # entity = user
        filename = "tests/tmp/test_entity_save"
        usr = self.usr
        x.to_file(filename, usr)
        usr2 = x.load_usr(filename)
        self.assertEqual(usr.ID, usr2.ID)
        keys1 = usr.key_pair
        keys2 = usr2.key_pair
        self.assertEqual(keys1, keys2)
        for k in usr.database.keys():
            self.assertEqual(usr.database[k], usr2.database[k])
        for k in usr2.database.keys():
            self.assertEqual(usr.database[k], usr2.database[k])

        # entity = service
        src = self.src
        x.to_file(filename, src)
        src2 = x.load_src(filename)
        self.assertEqual(src.ID, src2.ID)
        keys1 = src.key_pair
        keys2 = src2.key_pair
        self.assertEqual(keys1, keys2)
        for k in src.database.keys():
            self.assertEqual(src.database[k], src2.database[k])
        for k in src2.database.keys():
            self.assertEqual(src.database[k], src2.database[k])

        # entity = inspector
        insp = self.insp
        x.to_file(filename, insp)
        insp2 = x.load_insp(filename)
        self.assertEqual(insp.ID, insp2.ID)
        self.assertEqual(insp.scope, insp2.scope)
        self.assertEqual(insp.vko_pair, insp2.vko_pair)
        self.assertEqual(insp.sign_pair, insp2.sign_pair)
        for k in insp.database.keys():
            self.assertEqual(insp.database[k], insp2.database[k])
        for k in insp2.database.keys():
            self.assertEqual(insp.database[k], insp2.database[k])

        # entity = auth center
        auth = self.auth 
        x.to_file(filename, auth)
        auth2 = x.load_auth(filename)
        self.assertEqual(auth.total_ids, auth2.total_ids)
        self.assertEqual(auth.users, auth2.users)
        self.assertEqual(auth.id_scope, auth2.id_scope)
        self.assertEqual(auth.services, auth2.services)
        self.assertEqual(auth.inspectors_sig, auth2.inspectors_sig)
        self.assertEqual(auth.inspectors_vko, auth2.inspectors_vko)



if __name__ == "__main__":
    unittest.main()
