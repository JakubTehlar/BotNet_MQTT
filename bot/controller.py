import argparse

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
