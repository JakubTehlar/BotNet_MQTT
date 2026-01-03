import paho.mqtt.client as mqtt
import base64
from globvars import DEFAULT_BROKER_ADDRESS, DEFAULT_PORT, DEFAULT_TOPIC
from globvars import STANDARD_ALPHABET, CUSTOM_ALPHABET, ROOT_SECRET
from datetime import datetime
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from protocol import ProtocolHandler
from controller import BotController

class Client:
    def _on_connect(self, client, userdata, flags, reason_code, properties):
        print(f"Connected with result code {reason_code}")
        client.subscribe(self.topic)
    
    #     You must hide your communication and the controller should not be easily detected as 'bots' in the topic.
    # Filter those messages meant for the bot
    def _on_message(self, client, userdata, message):
        raw_payload = message.payload.decode()
        try:
            decoded = base64.b32decode(raw_payload).decode(errors="ignore")
            print(f"Message received on topic {message.topic}: {decoded}")
        except Exception as e:
            print(f"(!) Failed to decode message: {e}")
            print(f"Message received on topic {message.topic}: {raw_payload}")


    def connect(self):
        self.client.connect(self.broker_address, self.port)
        self.client.loop_forever()

    def __init__(self,
                 broker_address:str,
                 port: int,
                 topic: str):
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2) # taken from the docs 
        self.broker_address = broker_address
        self.port = port
        self.topic = topic
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

class Bot:
    def __init__(self,
                 broker_address:str = DEFAULT_BROKER_ADDRESS,
                 port: int = DEFAULT_PORT,
                 topic: str = DEFAULT_TOPIC):
        self.broker_address = broker_address
        self.port = port
        self.topic = topic
        self.client = Client(broker_address, port, topic)
    
    def start(self):
        self.client.connect()


def main():
    # bot = Bot(broker_address=DEFAULT_BROKER_ADDRESS,
    #           port=DEFAULT_PORT,
    #           topic=DEFAULT_TOPIC)
    # bot.start()
    bot_cont = BotController()
    message = ""
    with open("out_frame.bin", "rb") as f:
        message = f.read()
    print("Loaded message from out_frame.bin")
    protocol_handler = ProtocolHandler(secret=bot_cont.secret)
    decoded_m = protocol_handler.decode_frame(message)
    print(protocol_handler.verify_frame(decoded_m))

    # unpack the message
    magic, ver, cmd_type, length, auth, payload, checksum = decoded_m

if __name__ == "__main__":
    main()