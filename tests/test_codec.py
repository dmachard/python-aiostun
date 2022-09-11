import unittest
import aiostun



class TestDecode(unittest.TestCase):
    def test_valid_binding_request(self):
        """decode Binding Request"""
        codec = aiostun.Codec()

        # Message Type = Binding Success Response
        Binding_Req = "0001"
        # Message Length 
        Binding_Req += "0000"
        # Message Cookie
        Binding_Req += "2112a442"
        # Message Transaction Id
        Binding_Req += "7a54477269564651786d7749"

        codec.buf = bytes.fromhex(Binding_Req)
        decoded = codec.decode()
       
        self.assertIsNotNone(decoded)

    def test_valid_binding_success_response(self):
        """decode Binding Success response"""
        codec = aiostun.Codec()

        # Message Type = Binding Success Response
        Binding_Success = "0101"
        # Message Length 
        Binding_Success += "0048"
        # Message Cookie
        Binding_Success += "2112a442"
        # Message Transaction Id
        Binding_Success += "7a54477269564651786d7749"
        # Attribute XOR-MAPPED-ADDRESS
        Binding_Success += "002000080001a8e877ff14ec"
        # Attribute MAPPED-ADDRESS
        Binding_Success += "00010008000189fa56edb0ae"
        # Attribute RESPONSE-ORIGIN
        Binding_Success += "802b000800010050d827fc0f"
        # Attribute SOFTWARE
        Binding_Success += "80220018436f7475726e2d342e352e32202764616e20456964657227"
        # Attribute FINGERPRINT
        Binding_Success += "80280004d7caaa2b"

        codec.buf = bytes.fromhex(Binding_Success)
        decoded = codec.decode()
        
        self.assertIsNotNone(decoded)

    def test_invalid_binding_request(self):
        """decode invalid Binding Request"""
        codec = aiostun.Codec()

        # Message Type = Binding Success Response
        Binding_Req = "0001"
        # Message Length 
        Binding_Req += "0010"
        # Message Cookie
        Binding_Req += "2112a442"
        # Message Transaction Id
        Binding_Req += "7a54477269564651786d7749"

        codec.buf = bytes.fromhex(Binding_Req)
        decoded = codec.decode()
       
        self.assertIsNone(decoded)

    def test_invalid_binding_success_response(self):
        """decode Binding Success response"""
        codec = aiostun.Codec()

        # Message Type = Binding Success Response
        Binding_Success = "0101"
        # Message Length 
        Binding_Success += "0048"
        # Message Cookie
        Binding_Success += "2112a442"
        # Message Transaction Id
        Binding_Success += "7a54477269564651786d7749"
        # Attribute XOR-MAPPED-ADDRESS
        Binding_Success += "002000080001a8e877ff14ec"
        # Attribute MAPPED-ADDRESS
        Binding_Success += "00010008000189fa56edb0ae"
        # Attribute RESPONSE-ORIGIN
        Binding_Success += "802b000800010050d827fc0f"
        # Attribute SOFTWARE, invalid length
        Binding_Success += "80220018436f7475726e2d342e352e"
        # Attribute FINGERPRINT
        Binding_Success += "80280004d7caaa2b"

        codec.buf = bytes.fromhex(Binding_Success)
        decoded = codec.decode()
        
        self.assertIsNone(decoded)


class TestEncode(unittest.TestCase):
    def test_binding_request(self):
        codec = aiostun.Codec()

        # encode message
        req = aiostun.Message(msgclass=aiostun.CLASS_REQUEST, msgmethod=aiostun.METHOD_ALLOCATE, attrs=[])
        msg = codec.encode(req)

        # decode it
        codec.buf = msg
        decoded = codec.decode()
       
        self.assertIsNotNone(decoded)