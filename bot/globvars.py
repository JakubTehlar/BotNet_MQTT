DEFAULT_BROKER_ADDRESS = "147.32.82.209"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "sensors"

# VERIFICATION VARIABLES
PROTOCOL_VERSION = "1.0"
MAX_FRAME_SIZE = 1024  # bytes; by far covers all commands
MIN_FRAME_SIZE = 16    # bytes; minimum size to avoid trivial messages 
TIME_WINDOW_SECONDS = 120  # 2 minutes time window for replay attack prevention
ENCODING_VARIANT_ID = 1  # Identifier for the non-standard base64 alphabet
