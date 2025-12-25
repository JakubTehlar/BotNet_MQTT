import paho.mqtt.client as mqtt

DEFAULT_BROKER_ADDRESS = "147.32.82.209"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "sensors"
class Bot:
    def __init__(self,
                 broker_address:str = DEFAULT_BROKER_ADDRESS,
                 port: int = DEFAULT_PORT,
                 topic: str = DEFAULT_TOPIC):
        self.broker_address = broker_address
        self.port = port
        self.topic = topic



def main():
    pass

if __name__ == "__main__":
    main()