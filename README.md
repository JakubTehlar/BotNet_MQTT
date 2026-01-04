## Controller CLI Options

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

## Bot

The Bot listens for commands from the Controller on a specified MQTT topic (specified in either `bot/globvars.py` or `bot/bot.py` and `bot/controller.py`). It verifies message authenticity using a shared secret and only executes valid commands. Supported commands include:

- Announce presence (heartbeat / ping)
- List users
- List directory contents
- Get user ID
- Copy files
- Execute binaries
- Kill (terminate)

The Bot responds to commands with status and data, using the same protocol for replies.

## Controller

The Controller sends commands to the Bot in the following way. It builds protocol frames, encodes them, and publishes to the topic. The Controller expects a response and verifies their authenticity. Only the Controller with the correct secret can control the Bot.

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

## Security Features

- HMAC authentication for all messages
- Random padding and custom encoding for stealth
- Replay attack prevention using time windows

## File Structure

- `bot/` - Main source code
	- `bot.py` - Bot implementation
	- `controller.py` - Controller implementation
	- `protocol.py` - Protocol logic
	- `globvars.py` - Global constants and configuration

## Notes

- This project is not to be distributed with malicious intent.