import base64
import json
import hashlib
import os
import subprocess
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from ..utils import download_certificate


class JAdESValidator:
    """
    Class responsible for validating a signed JAdES document.
    It verifies the signature, validates the timestamp, and checks the certificate chain.
    """

    def __init__(self, signed_jades_file, cache_dir=".cache_dir"):
        self.signed_jades = self.load_signed_jades(signed_jades_file)
        self.payload = self.signed_jades['payload']
        self.protected_headers_base64 = self.signed_jades['protected']
        self.unsigned_headers = self.signed_jades['header']
        self.signature = self.signed_jades['signature']
        self.cache_dir = cache_dir

        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

    @staticmethod
    def load_signed_jades(signed_jades_file):
        with open(signed_jades_file, 'r') as f:
            return json.load(f)

    @staticmethod
    def base64url_decode(data):
        return base64.urlsafe_b64decode(data + '==')

    def decode_payload_and_headers(self):
        decoded_payload = self.base64url_decode(self.payload).decode('utf-8')
        decoded_protected_headers = json.loads(self.base64url_decode(self.protected_headers_base64).decode('utf-8'))
        return decoded_payload, decoded_protected_headers

    @staticmethod
    def get_kid_from_base64_cert(cert):
        cert_base64 = base64.b64encode(cert).decode()
        return base64.urlsafe_b64encode(hashlib.sha256(cert_base64.encode()).digest()).decode().rstrip("=")

    def find_cert_by_kid(self, decoded_protected_headers):
        x5c = decoded_protected_headers.get('x5c')
        kid = decoded_protected_headers.get('kid')

        for i, cert_base64 in enumerate(x5c):
            cert_der = base64.b64decode(cert_base64)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            cert_kid = self.get_kid_from_base64_cert(cert_der)

            if cert_kid == kid:
                return cert.public_key(), cert

        raise ValueError("Certificate matching kid not found")

    def verify_signature(self, public_key):
        signing_data = f"{self.protected_headers_base64}.{self.payload}"
        signature_bytes = self.base64url_decode(self.signature)

        try:
            public_key.verify(
                signature_bytes,
                signing_data.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True, hashlib.sha256(signing_data.encode()).hexdigest()
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False, None

    def extract_openssl_ts_reply(self, received_tst_path):
        """
        Extracts timestamp information from the OpenSSL TS reply using 'openssl ts -reply -in response.tsr -text'.
        :param received_tst_path: Path to the timestamp token file.
        :return: A dictionary with parsed timestamp information.
        """
        result = subprocess.run(
            ['openssl', 'ts', '-reply', '-in', received_tst_path, '-text'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        if result.returncode != 0:
            return {"error": result.stderr.decode()}

        ts_reply_output = result.stdout.decode()
        parsed_info = {}

        # Parse the OpenSSL output for relevant data
        lines = ts_reply_output.splitlines()
        for line in lines:
            if "Status:" in line:
                parsed_info["status"] = line.split("Status:")[1].strip()
            if "Serial number:" in line:
                parsed_info["serial_number"] = line.split("Serial number:")[1].strip()
            if "Time stamp:" in line:
                parsed_info["timestamp"] = line.split("Time stamp:")[1].strip()
            if "Nonce:" in line:
                parsed_info["nonce"] = line.split("Nonce:")[1].strip()
            if "Hash Algorithm:" in line:
                parsed_info["hash_algorithm"] = line.split("Hash Algorithm:")[1].strip()
            if "Message data:" in line:
                parsed_info["message_data"] = lines[lines.index(line) + 1].strip()  # Take the next line for the data

        return parsed_info

    def verify_timestamp(self, signing_data):
        timestamp_metadata = {}
        for item in self.unsigned_headers.get('etsiU', []):
            if 'sigTst' in item and 'tstTokens' in item['sigTst'] and len(item['sigTst']['tstTokens']) > 0:
                time_stamp_token = item['sigTst']['tstTokens'][0]['val']
                time_stamp_token_bytes = self.base64url_decode(time_stamp_token)

                received_tst_path = os.path.join(self.cache_dir, 'received_tst.tsr')
                with open(received_tst_path, 'wb') as f:
                    f.write(time_stamp_token_bytes)

                data_hash_path = os.path.join(self.cache_dir, 'data_hash.bin')
                data_hash = hashlib.sha256(signing_data.encode()).digest()
                with open(data_hash_path, 'wb') as f:
                    f.write(data_hash)

                tsa_cert_url = 'https://freetsa.org/files/tsa.crt'
                ca_cert_url = 'https://freetsa.org/files/cacert.pem'

                tsa_cert_path = os.path.join(self.cache_dir, 'tsa.crt')
                ca_cert_path = os.path.join(self.cache_dir, 'cacert.pem')

                download_certificate(tsa_cert_url, tsa_cert_path)
                download_certificate(ca_cert_url, ca_cert_path)

                # Use OpenSSL to verify the timestamp response
                result = subprocess.run(
                    ['openssl', 'ts', '-verify', '-in', received_tst_path, '-data', data_hash_path, '-untrusted', tsa_cert_path, '-CAfile', ca_cert_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

                timestamp_metadata = {
                    "tsa_cert_url": tsa_cert_url,
                    "ca_cert_url": ca_cert_url,
                    "timestamp_hex": time_stamp_token_bytes.hex(),
                    "data_hash": data_hash.hex(),
                    "openssl_output": result.stdout.decode(),
                    "openssl_error": result.stderr.decode(),
                }

                # Extract extra timestamp info using openssl ts -reply -in response.tsr -text
                timestamp_info = self.extract_openssl_ts_reply(received_tst_path)
                timestamp_metadata.update(timestamp_info)

                return result.returncode == 0, timestamp_metadata

        return False, {}

    def validate_certificate_chain(self, decoded_protected_headers):
        """
        Validates the certificate chain from the x5c field in the protected headers.
        Verifies that each certificate is signed by the next certificate in the chain.
        Collects metadata for each certificate and its parent certificate.
        :param decoded_protected_headers: The decoded protected headers as a dictionary.
        :return: Tuple of (is_chain_valid, certificate_chain_metadata).
        """
        x5c = decoded_protected_headers.get('x5c')
        certificates = [x509.load_der_x509_certificate(base64.b64decode(cert_base64), default_backend()) for cert_base64 in x5c]
        cert_chain_metadata = []

        for i in range(len(certificates)):
            cert = certificates[i]
            cert_metadata = {
                "certificate_subject": cert.subject.rfc4514_string(),
                "certificate_serial_number": cert.serial_number,
                "certificate_valid_from": cert.not_valid_before_utc.isoformat(),
                "certificate_valid_to": cert.not_valid_after_utc.isoformat(),
                "verified": None,
            }

            # For all but the last certificate in the chain, validate against the issuer
            if i < len(certificates) - 1:
                issuer_cert = certificates[i + 1]
                issuer_public_key = issuer_cert.public_key()

                try:
                    issuer_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                    cert_metadata["issuer_certificate"] = {
                        "issuer_certificate_subject": issuer_cert.subject.rfc4514_string(),
                        "issuer_certificate_serial_number": issuer_cert.serial_number,
                        "issuer_certificate_valid_from": issuer_cert.not_valid_before_utc.isoformat(),
                        "issuer_certificate_valid_to": issuer_cert.not_valid_after_utc.isoformat(),
                        "verified": True
                    }
                except Exception as e:
                    cert_metadata["issuer_certificate"] = {
                        "issuer_certificate_subject": issuer_cert.subject.rfc4514_string(),
                        "issuer_certificate_serial_number": issuer_cert.serial_number,
                        "issuer_certificate_valid_from": issuer_cert.not_valid_before_utc.isoformat(),
                        "issuer_certificate_valid_to": issuer_cert.not_valid_after_utc.isoformat(),
                        "verified": False,
                        "error": str(e)
                    }
                    return False, cert_chain_metadata

            # # If this is the last certificate (self-signed root), mark it as root
            # if i == len(certificates) - 1:
            #     cert_metadata["issuer_certificate"] = {
            #         "issuer_certificate_subject": "Root Certificate (self-signed)",
            #         "issuer_certificate_serial_number": cert.serial_number,
            #         "issuer_certificate_valid_from": cert.not_valid_before.isoformat(),
            #         "issuer_certificate_valid_to": cert.not_valid_after.isoformat(),
            #         "verified": "self-signed"
            #     }

            cert_chain_metadata.append(cert_metadata)

        return True, cert_chain_metadata


    def validate(self, output_file="validation_result.json"):
        decoded_payload, decoded_protected_headers = self.decode_payload_and_headers()
        public_key, kid_cert = self.find_cert_by_kid(decoded_protected_headers)

        signature_valid, signature_hash = self.verify_signature(public_key)
        certificate_chain_valid, cert_chain_metadata = self.validate_certificate_chain(decoded_protected_headers)

        signing_data = f"{self.protected_headers_base64}.{self.payload}"
        timestamp_valid, timestamp_metadata = self.verify_timestamp(signing_data)

        protected_headers_readable = decoded_protected_headers

        # Add signature time validation
        signature_time = timestamp_metadata.get("timestamp")
        signature_time_valid = False
        if signature_time:
            try:
                # Parse the timestamp and add timezone information (UTC)
                signature_time_dt = datetime.strptime(signature_time, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                
                cert_not_before = kid_cert.not_valid_before_utc
                cert_not_after = kid_cert.not_valid_after_utc

                # Check that the signature time is between not_before and not_after
                if cert_not_before <= signature_time_dt <= cert_not_after:
                    signature_time_valid = True
                else:
                    print(f"Signature time {signature_time_dt} is outside the certificate's validity period.")
            except Exception as e:
                print(f"Error while parsing or validating signature time: {e}")
        
        validation_result = {
            "signature_valid": signature_valid,
            "timestamp_valid": timestamp_valid,
            "signature_time_valid": signature_time_valid,
            "certificate_chain_valid": certificate_chain_valid,
            #"signature_hash": signature_hash,
            "certificate_chain_metadata": cert_chain_metadata,
            "timestamp_metadata": timestamp_metadata,
            "kid_certificate_subject": kid_cert.subject.rfc4514_string(),
            #"kid_certificate_serial_number": kid_cert.serial_number,
            "kid_certificate_not_before": cert_not_before.isoformat(),
            "kid_certificate_not_after": cert_not_after.isoformat(),
            "protected_headers": protected_headers_readable,
        }

        with open(output_file, 'w') as f:
            json.dump(validation_result, f, indent=4)

        print(f"Validation result saved in {output_file}")