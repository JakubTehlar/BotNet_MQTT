from cryptography.hazmat.primitives import hashes, hmac
import os
import random
import struct
import zlib
from globvars import STANDARD_ALPHABET, CUSTOM_ALPHABET, ROOT_SECRET, MAGIC_BYTES, PROTOCOL_VERSION, MAX_FRAME_SIZE, MIN_FRAME_SIZE

class ProtocolHandler:
    def __init__(self, secret: bytes=ROOT_SECRET.encode()):
        self.secret = secret

    def _compute_auth_tag(self, session_key: bytes, payload: bytes) -> bytes:
        h = hmac.HMAC(session_key, hashes.SHA256())
        h.update(payload)
        return h.finalize()

    def _build_frame(self, cmd_type, payload) -> dict:
        if len(payload) > MAX_FRAME_SIZE:
            raise ValueError("Payload size exceeds maximum frame size.")
        if len(payload) < MIN_FRAME_SIZE:
            raise ValueError("Payload size below minimum frame size.")
        if not isinstance(payload, bytes):
            raise TypeError("Payload must be of type bytes.")
        
        auth = self._compute_auth_tag(self.secret, payload)
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

    def _encode_frame(self, frame: bytes) -> bytes:
        # blend with the noise
        pad_before = random.randint(0, 16)
        pad_after = random.randint(0, 16)

        prefix = os.urandom(pad_before)
        suffix = os.urandom(pad_after)

        blend_frame = prefix + frame + suffix
        return blend_frame

    def _decode_frame(self, data: bytes) -> bytes | None:
        magic = MAGIC_BYTES
        magic_index = data.find(magic)

        # Fail
        if magic_index == -1:
            print("Magic bytes not found.")
            return None

        try:
            header_size = struct.calcsize("!2s B B H 32s")
            header = data[magic_index:magic_index + header_size]
            (magic, version, cmd_type, length, auth) = struct.unpack("!2s B B H 32s", header)

            payload_start = magic_index + header_size
            payload_end = payload_start + length
            payload = data[payload_start:payload_end]
            checksum = struct.unpack("!I", data[payload_end:payload_end + 4])[0]
        except Exception as e:
            print(f"Failed to unpack frame: {e}")
            return None
        
        if version != PROTOCOL_VERSION:
            print("Version mismatch.")
            return None
        
        if zlib.crc32(payload) & 0xffffffff != checksum:
            print("Checksum mismatch.")
            return None
    
        expected_auth = self._compute_auth_tag(self.secret, payload)
        if auth != expected_auth:
            print("Authentication failed.")
            return None

        return payload 