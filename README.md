# Python Project for Secure Image Management

This project provides a comprehensive Python script for managing container images within a secure environment, leveraging Google Cloud services such as Binary Authorization and Container Analysis. It includes functionalities for sending HTTP requests, executing shell commands, generating and verifying image descriptions, attestation payloads, and more, with an emphasis on security and integrity verification.

## Features

- Generate and verify image descriptions and attestation payloads.
- Utilize Google Cloud KMS for cryptographic operations.
- Manage attestations in Google Cloud Binary Authorization.

## Requirements

- Python 3.6 or later.
- Access to Google Cloud services, including Binary Authorization and Container Analysis.
- A Google Cloud account with permissions to manage KMS, GKE, and associated APIs.
- Before using the script you must be authenticated with a user that has the rights to perform those operations.
```bash
gcloud config set account <yourserviceaccount>
```

## Installation

1. Clone the repository to your local machine
2. Navigate into the project directory
3. Install the required dependencies (it's recommended to use a virtual environment)

```bash
cd signer
pip install -r requirements.txt
```

## Usage
Setting Environment Variables
The script expects certain environment variables to be set for its operation. These include:

- IMAGE_PATH: The path to the image in the registry.
- IMAGE_DIGEST: The digest of the image.
- ATTESTOR_PROJECT_NAME: The name of the project where the attestor is located.
- ATTESTOR_NAME: The name of the attestor.
- ATTESTOR_KEY_ID: The ID of the key used by the attestor (optional).

Before running the script, ensure you have configured your Google Cloud SDK and have the necessary permissions set up. The script can be executed as follows:

```bash
cd signer
python sign_image.py
```
