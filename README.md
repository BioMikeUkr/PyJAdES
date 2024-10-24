
# PyJAdES
A simple prototype Python library for signing and validating JAdES documents. PyJAdES is a Python library designed to work with JAdES signatures. It allows users to sign payloads with digital certificates and validate signed documents. Created at Vilnius University during the course *Electronic Signature Infrastructure and Electronic Documents* due to the lack of available open-source solutions for experimenting with JAdES.

#### ! This project is primarily for experimentation and learning, and should not be used in production systems.

### Requirements Table

| Requirement       | Version/Details    |
|-------------------|--------------------|
| Python            | >= 3.7             |
| OpenSSL           | sudo apt install openssl (Linux) or brew install openssl (macOS) |
| cryptography      | >= 41.0.1          |
| requests          | >= 2.31.0          |

### Installation
```bash
pip install git+https://github.com/BioMikeUkr/PyJAdES.git
```

### Quickstart
Here's an example of how you can sign and validate a JSON payload using PyJAdES.

```python
from pyjades import JAdESSigner, JAdESValidator

payload_to_sign = "Important data"

signer = JAdESSigner(
    key_file="certificates/new_cert_key.pem",
    cert_file="certificates/new_cert_signed.pem",
    intermediate_cert_file="certificates/intermediateCA_cert.pem"
)

signer.sign(payload_to_sign, output_file="signed_dock.json")

# JAdESValidator
validator = JAdESValidator('signed_dock.json')
validator.validate(output_file="validation_result.json")
```

You can also find an example notebook in the repository.

### Additional Fields
You can include any signed and unsigned header described in [ETSI TS 119 182-1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf), but here are simple examples.

```json
# Additional headers to include in the signed document
additional_signed_headers = {
    "sigPl": {
        "addressCountry": "LT",
        "addressLocality": "Vilnius",
        "addressRegion": "Vilnius",
        "postOfficeBoxNumber": "24",
        "postalCode": "LT-03225",
        "streetAddress": "Naugarduko g. 24"
    }
}

# Optional custom fields for ETSI compliance
additional_etsiU = {
    "etsiU": [
        {
            "customField": "Some value"
        }
    ]
}
```

To run the script with additional fields, indicate these fields in `signer.sign()` as in the example:

```python
from pyjades import JAdESSigner, JAdESValidator

payload_to_sign = "Important data"
additional_signed_headers = {
    "sigPl": {
        "addressCountry": "LT",
        "addressLocality": "Vilnius",
        "addressRegion": "Vilnius",
        "postOfficeBoxNumber": "24",
        "postalCode": "LT-03225",
        "streetAddress": "Naugarduko g. 24"
    }
}

additional_etsiU = {
    "etsiU": [
        {
            "customField": "Some value"
        }
    ]
}

signer = JAdESSigner(
    key_file="certificates/new_cert_key.pem",
    cert_file="certificates/new_cert_signed.pem",
    intermediate_cert_file="certificates/intermediateCA_cert.pem"
)

signer.sign(payload_to_sign, additional_signed_headers, additional_etsiU, output_file="signed_dock.json")

# JAdESValidator
validator = JAdESValidator('signed_dock.json')
validator.validate(output_file="validation_result.json")
```

### Documentation
Developed according to the [ETSI TS 119 182-1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf).
