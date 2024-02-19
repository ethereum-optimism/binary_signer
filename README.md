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

```bash
cd signer

python sign_image.py [--image-path IMAGE_PATH] [--source-image-path SOURCE_IMAGE_PATH]
[--destination-artifact-repository DESTINATION_ARTIFACT_REPOSITORY]
[--attestor-project-name ATTESTOR_PROJECT_NAME] [--attestor-name ATTESTOR_NAME]
[--attestor-key-id ATTESTOR_KEY_ID] [--signer-logging-level LOGGING_LEVEL] [--command COMMAND]
[--platform PLATFORM]

```

### Options

- `--image-path`: Path to the Docker image to be signed.
- `--source-image-path`: Source image path for transfer and sign commands.
- `--destination-artifact-repository`: Destination repository for transferring images.
- `--attestor-project-name`: Project ID of the attestor.
- `--attestor-name`: Name of the attestor.
- `--attestor-key-id`: Key ID for the attestor.
- `--signer-logging-level`: Logging level (`CRITICAL`, `FATAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`).
- `--command`: Command to execute (`sign`, `verify`, `transfer`, `transfer-and-sign`).
- `--platform`: Platform used for pulling images.

## Classes

### GCPLogin

- Handles Google Cloud Platform login and access token retrieval.

### DockerImage

- Represents a Docker image and provides methods for pulling and pushing images.

### GoogleArtifactoryImage

- Subclass of `DockerImage` specialized for Google Artifactory images.

### GoogleKMS

- Manages Google Key Management Service (KMS) operations.

### GoogleBinaryAuthorizationAttestor

- Manages attestor operations for binary authorization.

## Functions

- `get_command_line_args()`: Parses command line arguments.
- `sign_image(gcp_login, image_path, attestor_name, attestor_project_id, attestor_key_id)`: Signs a Docker image.
- `verify_image(gcp_login, image_path, attestor_name, attestor_project_id)`: Verifies the signature of a Docker image.
- `transfer(gcp_login, source_image_path, destination_artifact_repository)`: Transfers a Docker image to a destination repository.
- `set_logging_level(logging_level)`: Sets the logging level.
- `main()`: Main function to execute commands based on user input.



