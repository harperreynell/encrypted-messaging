import socket
import struct
import time
from locust import User, task, between
from nacl.public import PrivateKey
from nacl.bindings import (
    crypto_kx_client_session_keys,
    crypto_aead_chacha20poly1305_ietf_encrypt
)

class PacketType:
    HANDSHAKE = 0
    CONTROL = 1
    TEXT = 2
    ROOM_KEY = 3

class EncryptedMessengerUser(User):
    wait_time = between(1, 5)

    def on_start(self):
        self.sock = None
        self.tx_key = None
        self.rx_key = None

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect(("127.0.0.1", 8080))

            self.priv_key = PrivateKey.generate()
            self.pub_key_bytes = bytes(self.priv_key.public_key)

            server_pub = self.sock.recv(32)
            if len(server_pub) != 32:
                raise Exception("Не вдалося отримати публічний ключ сервера")

            self.sock.sendall(self.pub_key_bytes)

            self.rx_key, self.tx_key = crypto_kx_client_session_keys(
                self.pub_key_bytes, bytes(self.priv_key), server_pub
            )

            username = f"Locust_{id(self)}"
            self.send_encrypted_packet(PacketType.HANDSHAKE, username.encode())

            self.fire_locust_event("Connect", success=True)

        except Exception as e:
            self.fire_locust_event("Connect", success=False, exception=e)
            if self.sock:
                self.sock.close()

    def send_encrypted_packet(self, p_type, payload):
        inner_packet = struct.pack("!BI", p_type, len(payload)) + payload

        nonce = socket.os.urandom(12)
        ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(inner_packet, None, nonce, self.tx_key)

        encrypted_payload = nonce + struct.pack("!I", len(ciphertext)) + ciphertext
        network_packet = struct.pack("!I", len(encrypted_payload)) + encrypted_payload

        self.sock.sendall(network_packet)

    @task
    def send_chat_message(self):
        if not self.tx_key:
            return

        start_time = time.time()
        try:
            msg = f"Повідомлення від бота {id(self)}"
            self.send_encrypted_packet(PacketType.TEXT, msg.encode())

            self.fire_locust_event(
                "SendMessage",
                success=True,
                resp_time=int((time.time() - start_time) * 1000),
                length=len(msg)
            )
        except Exception as e:
            self.fire_locust_event(
                "SendMessage",
                success=False,
                resp_time=int((time.time() - start_time) * 1000),
                exception=e
            )

    def fire_locust_event(self, name, success, resp_time=0, length=0, exception=None):
        self.environment.events.request.fire(
            request_type="TCP",
            name=name,
            response_time=resp_time,
            response_length=length,
            exception=exception if not success else None
        )

    def on_stop(self):
        if self.sock:
            self.sock.close()