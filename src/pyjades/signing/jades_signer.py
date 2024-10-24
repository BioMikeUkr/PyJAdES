import base64
import json
import hashlib
import os
import subprocess
import requests
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from datetime import datetime, timezone

class JAdESSigner:
    """
    Class responsible for signing a payload using a provided certificate and key.
    Generates the signature, headers, and timestamp and stores the result in JSON format.
    """

    def __init__(self, key_file, cert_file, intermediate_cert_file, cache_dir: str = "./cache"):
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
        self.cache_dir = cache_dir
        self.key = self.load_key(key_file)
        self.cert = self.load_cert(cert_file)
        self.intermediate_cert = self.load_cert(intermediate_cert_file)

    @staticmethod
    def load_key(key_file):
        with open(key_file, "rb") as f:
            return load_pem_private_key(f.read(), password=None)

    @staticmethod
    def load_cert(cert_file):
        with open(cert_file, "rb") as f:
            return load_pem_x509_certificate(f.read())

    @staticmethod
    def base64url_encode(data):
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    @staticmethod
    def get_cert_digest(cert):
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
        return JAdESSigner.base64url_encode(hashlib.sha256(cert_der).digest())

    @staticmethod
    def get_kid_from_base64_cert(cert):
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
        cert_base64 = base64.b64encode(cert_der).decode()
        return JAdESSigner.base64url_encode(hashlib.sha256(cert_base64.encode()).digest())

    @staticmethod
    def get_current_utc_time():
        return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def generate_protected_headers(self, payload, additional_signed_headers=None):
        """
        Generates and returns protected headers including custom fields passed in additional_signed_headers.
        :param payload: The data to be signed.
        :param additional_signed_headers: Dictionary of additional parameters to be used in protected headers.
        :return: Base64-encoded protected headers.
        """
        if additional_signed_headers is None:
            additional_signed_headers = {}

        # Default protected headers structure
        headers = {
            "alg": "RS256",
            "cty": "json",
            "typ": "jose+json",
            "x5c": [
                base64.b64encode(self.cert.public_bytes(encoding=serialization.Encoding.DER)).decode(),
                base64.b64encode(self.intermediate_cert.public_bytes(encoding=serialization.Encoding.DER)).decode(),
            ],
            "kid": self.get_kid_from_base64_cert(self.cert),
            "sigX5ts": [
                {"digAlg": "2.16.840.1.101.3.4.2.1", "digVal": self.get_cert_digest(self.cert)},
                {"digAlg": "2.16.840.1.101.3.4.2.1", "digVal": self.get_cert_digest(self.intermediate_cert)}
            ],
            "sigT": self.get_current_utc_time()
        }

        # Merge provided additional signed headers
        headers.update(additional_signed_headers)

        return self.base64url_encode(json.dumps(headers).encode())

    def sign_payload(self, payload, additional_signed_headers=None):
        """
        Signs the payload and returns the signature, protected headers, and payload in base64url format.
        :param payload: The data to be signed.
        :param additional_signed_headers: Custom parameters for headers.
        :return: Signature, protected headers, and payload.
        """
        payload_base64 = self.base64url_encode(payload.encode())
        protected_headers_base64 = self.generate_protected_headers(payload, additional_signed_headers)
        signing_data = f"{protected_headers_base64}.{payload_base64}"

        signature = self.key.sign(
            signing_data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_base64url = self.base64url_encode(signature)

        return signature_base64url, protected_headers_base64, payload_base64

    def generate_tsa_request(self, signing_data):
        data_hash = hashlib.sha256(signing_data.encode()).digest()
        data_hash_path = os.path.join(self.cache_dir, 'data_hash.bin')
        with open(data_hash_path, 'wb') as f:
            f.write(data_hash)

        # Use openssl to create the TSA request
        subprocess.run(['openssl', 'ts', '-query', '-data', data_hash_path, '-no_nonce', '-sha256', '-out', os.path.join(self.cache_dir, 'request.tsr')])

        with open(os.path.join(self.cache_dir, 'request.tsr'), 'rb') as f:
            response = requests.post('https://freetsa.org/tsr', headers={'Content-Type': 'application/timestamp-query'}, data=f)

        with open(os.path.join(self.cache_dir, 'response.tsr'), 'wb') as f:
            f.write(response.content)

        with open(os.path.join(self.cache_dir, 'response.tsr'), 'rb') as f:
            return self.base64url_encode(f.read())

    def save_signed_document(self, signature, protected_headers_base64, payload_base64, time_stamp_token, additional_etsiU=None, output_file="signed_jades_with_cert_chain.json"):
        """
        Saves the signed document with protected headers, payload, and ETSI section.
        :param signature: The generated signature.
        :param protected_headers_base64: Base64-encoded protected headers.
        :param payload_base64: Base64-encoded payload.
        :param time_stamp_token: Time-stamp token generated by the TSA.
        :param additional_etsiU: Additional ETSI fields to include in the header.
        :param output_file: The file where the signed document is saved.
        """
        if additional_etsiU is None:
            additional_etsiU = {}

        timestamp_structure = {
            "sigTst": {
                "tstTokens": [
                    {
                        "val": time_stamp_token  # This will contain the base64-encoded timestamp token
                    }
                ]
            }
        }

        # Merge additional ETSI fields if provided
        etsiU_section = [timestamp_structure]
        etsiU_section.extend(additional_etsiU.get('etsiU', []))

        signed_jades = {
            "payload": payload_base64,
            "protected": protected_headers_base64,
            "header": {
                "etsiU": etsiU_section
            },
            "signature": signature
        }

        with open(output_file, 'w') as f:
            json.dump(signed_jades, f, indent=4)
        print(f"Signature saved in '{output_file}'")

    def sign(self, payload, additional_signed_headers=None, additional_etsiU=None, output_file="signed_jades_with_cert_chain.json"):
        """
        Main function to sign the payload and generate the JAdES structure.
        :param payload: The data to be signed.
        :param additional_signed_headers: Custom parameters to be used in protected headers.
        :param additional_etsiU: Additional parameters for ETSI section.
        :param output_file: The output file for the signed JSON.
        """
        signature, protected_headers_base64, payload_base64 = self.sign_payload(payload, additional_signed_headers)
        time_stamp_token = self.generate_tsa_request(f"{protected_headers_base64}.{payload_base64}")
        self.save_signed_document(signature, protected_headers_base64, payload_base64, time_stamp_token, additional_etsiU, output_file)
        