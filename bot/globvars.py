DEFAULT_BROKER_ADDRESS = "147.32.82.209"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "sensors"

# VERIFICATION VARIABLES
PROTOCOL_VERSION = "1"
MAX_FRAME_SIZE = 1024  # bytes; by far covers all commands
MIN_FRAME_SIZE = 16    # bytes; minimum size to avoid trivial messages 
TIME_WINDOW_SECONDS = 120  # 2 minutes time window for replay attack prevention
ENCODING_VARIANT_ID = 1  # Identifier for the non-standard base64 alphabet
ROOT_SECRET = "supersecretkey"  # Shared secret key for authentication
MAGIC_BYTES = b'\xAB\xCD'  # Example magic bytes for frame start

# COMMAND TYPES
CMD_TYPES = {
    "announce": 0x01,
    "list_users": 0x02,
    "list_dir": 0x03,
    "user_id": 0x04,
    "copy_file": 0x05,
    "exec_binary": 0x06
}

# Encoding 
STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CUSTOM_ALPHABET   = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"


