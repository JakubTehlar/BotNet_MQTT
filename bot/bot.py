import paho.mqtt.client as mqtt

DEFAULT_BROKER_ADDRESS = "147.32.82.209"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "sensors"

class Client:
    
    def _on_connect(self, userdata, flags, reason_code, properties):
        print(f"Connected with result code {reason_code}")
        self.client.subscribe(self.topic)
    
    def _on_message(self, userdata, message):
        print(f"Message received on topic {message.topic}: {str(message.payload)}")

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

class Bot:
    def __init__(self,
                 broker_address:str = DEFAULT_BROKER_ADDRESS,
                 port: int = DEFAULT_PORT,
                 topic: str = DEFAULT_TOPIC):
        self.broker_address = broker_address
        self.port = port
        self.topic = topic
        self.client = Client(broker_address, port, topic)
    
    def start(self):
        self.client.connect()


def main():
    pass

if __name__ == "__main__":
    main()