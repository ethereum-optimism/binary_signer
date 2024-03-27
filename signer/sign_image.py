import subprocess
import shlex
import json
import os, sys
import hashlib
import base64
import requests
from pprint import pprint
from urllib.parse import quote
import logging
import re
import argparse



class GCPLogin:
    def __init__(self):
        self.access_token=None
        self.current_user_email=self.retrieve_current_user_email()
        self.project_id=self.current_user_email.split("@")[1].split(".")[0]

        if not self.current_user_email:
            logging.critical("No user currently logged in. Make sure you have an active user in gcloud")
            raise Exception("No user found logged in")

    def get_project_id(self):
        return self.project_id
    
    def get_current_user_email(self):
        return self.current_user_email
    
    def get_access_token(self,force_refresh:bool=False):
        if force_refresh or not self.access_token:
            self.access_token=self.retrieve_access_token()
        return self.access_token
        
    def __str__(self):
        return f"GCPLogin(User: {self.current_user_email})"
    
    def retrieve_current_user_email(self):
        url = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json"
        response = self.send_request(url=url, method="GET", headers=None, data=None)
        if response['data'] and  "email" in response['data']:
            return response['data']['email']
        return None
    
    def retrieve_access_token(self):
        cmd = "gcloud auth print-access-token"
        stdout, stderr = self.execute_shell_command(cmd,timeout=2)

        if stderr is None:
            return stdout.strip()
        else:
            raise Exception("Failed to print access token. Please ensure you are properly authenticated and try again.")
    
    def send_request(self,url:str, method:str="GET", headers:dict=None, data:dict=None):
        """
        Send an HTTP request and return the response.

        :param url: URL to send the request to
        :param method: HTTP method (GET or POST)
        :param headers: Dictionary of headers to send with the request
        :param data: Data to send with the request. For GET requests, these will be converted to URL parameters; for POST requests, this will be the request body.
        :return: A dictionary with the status code, response data, and any error message.
        """
        try:
            if not url.startswith("https://"):
                raise ValueError("URL must start with https:// for security reasons")
            # Ensure headers and data are not None
            if headers is None:
                headers = {}
            if data is None:
                data = {}
            headers['Content-Type']="application/json"
            headers['Authorization']=f"Bearer {self.get_access_token()}"
            # Choose the request method
            if method.upper() == "GET":
                response = requests.get(url, headers=headers)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, data=data)
            else:
                return {"error": "Unsupported method specified"}

            # Check if the response was successful
            response.raise_for_status()

            # Return the response status code and content
            try:
                response_data = response.json()
            except ValueError:
                response_data = response.text
            return {
                "status_code": response.status_code,
                "data": response_data,  # or response.text if expecting text
                "error": None
            }
        except requests.RequestException as e:
            # Handle any errors that occur during the request
            return {
                "status_code": None,
                "data": None,
                "error": str(e)
            }
        
    def execute_shell_command(self,cmd:str,timeout:int=5):
        """
        Executes a shell command and returns the output.

        Parameters:
        - cmd (str): The command to execute.

        Returns:
        - A tuple containing the command's standard output and standard error.
        """
        if not isinstance(cmd, str) or ';' in cmd or '&&' in cmd or '||' in cmd:
            raise ValueError("Invalid command. Command must be a safe string.")
        try:
            # Use shlex.split to handle command parsing.
            process = subprocess.run(shlex.split(cmd), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,timeout=timeout)
            stdout = process.stdout
            return stdout, None  # Return stdout and None for stderr in case of success.
        except subprocess.CalledProcessError as e:
            return e.stdout, e.stderr  # Return both stdout and stderr in case of error.
        except subprocess.TimeoutExpired as e:
            return e.stdout, e.stderr



class DockerImage:
    def __init__(self, gcp_login:GCPLogin,image_path:str):
        self.gcp_login = gcp_login
        self.info={
            "name":None,
            "path":None,
            "digest":None,
            "tag":None,
            "fully_qualified_digest":None
        }

        pattern = r'^(?P<path>[\w\.\-\/]+)(?::(?P<tag>[\w\.\-]+))?(?:@sha256:(?P<digest>[a-fA-F0-9]{64}))?$'
        match = re.match(pattern, image_path)
        if match:
            self.info.update(match.groupdict())
        if "/" in self.info['path']:
            self.info['name']=self.info['path'].split("/")[-1]
        else:
            self.info['name']=self.info['path']
        if self.info['digest'] and not self.info['digest'].startswith("sha256:"):
            self.info['digest']=f"sha256:{self.info['digest']}"

        

    def get_image_description_payload(self) -> bytes:
        payload = {
            "critical": {
                "identity": {
                    "docker-reference": self.info['path']
                },
                "image": {
                    "docker-manifest-digest": self.info['digest']
                },
                "type": "Google cloud binauthz container signature"
            }
        }
        str_payload=json.dumps(payload, indent=0)
        return str_payload.encode('utf-8')
    
    def get_fully_qualified_digest(self)->str:
        return self.info['fully_qualified_digest']
    

    def __str__(self):
        return f"DockerImage: {self.info}"
    
    def get_image_name(self)->str:
        return self.info['name']

    def get_image_tag(self)->str:
        return self.info['tag']
    
    def pull(self,force_refresh=False,platform="amd64")->str:
        source_image_path=f"{self.info['path']}:{self.info['tag']}"
        # if not force_refresh:
        #     stdout, stderr =self.gcp_login.execute_shell_command(f"docker image inspect {source_image_path} --platform {platform}",timeout=60)
        #     if (stdout):
        #         logging.info(f"Image already exists locally {source_image_path}")
        #         return True

        logging.info(f"Pulling image {source_image_path}")
        stdout, stderr =self.gcp_login.execute_shell_command(f"docker pull {source_image_path} --platform {platform}",timeout=60)
        if (stderr):
            logging.critical(f"FAIL: Pulling image {source_image_path} {stderr}")
            return False
    
        return True

    def push(self,destination_image_path,force_refresh=False)->str:
        source_image_path=f"{self.info['path']}:{self.info['tag']}"
        logging.info(f"Tagging image {source_image_path} to {destination_image_path}")
        stdout, stderr = self.gcp_login.execute_shell_command(f"docker tag {source_image_path} {destination_image_path}",timeout=60)
        if (stderr):
            logging.critical(f"FAIL:Tagging image {source_image_path} to {destination_image_path} {stderr}")
            return None
        
        logging.info(f"Push image {destination_image_path}")
        stdout, stderr = self.gcp_login.execute_shell_command(f"docker push {destination_image_path}",timeout=60)
        if (stderr):
            logging.critical(f"FAIL:Push image {destination_image_path} {stderr}")
            return None

class GoogleArtifactoryImage(DockerImage):
    def __init__(self, gcp_login:GCPLogin, image_path:str):
        super().__init__(gcp_login,image_path)
        self.retrieve_image_info()

    def __str__(self):
        return f"GoogleArtifactoryImage: {self.info}"
    
    def retrieve_image_info(self):
        logging.info(f"Retriving docker image {self.info}")
        if not self.info['digest']:
            cmd=f"gcloud container images describe {self.info['path']}:{self.info['tag']} --format=json"
            stdout, stderr = self.gcp_login.execute_shell_command(cmd=cmd,timeout=2)
            try:
                json_obj=json.loads(stdout.strip())['image_summary']
                self.info['fully_qualified_digest']=json_obj['fully_qualified_digest']
                self.info['digest']=json_obj['digest']
            except:
                logging.warn("It was not possible to get Image digest")
                raise Exception("It was not possible to get Image digest")
        else:
            self.info['fully_qualified_digest']=f"{self.info['path']}@{self.info['digest']}"

    
    def get_base64_encoded_payload_hash(self)->str:
        payload=self.get_image_description_payload()
        sha512_hash = hashlib.sha512(payload).digest()
        base64_encoded_hash = base64.b64encode(sha512_hash).decode('utf-8')
        return base64_encoded_hash
    
    def get_base64_encoded_payload(self)->str:
        payload=self.get_image_description_payload()
        return base64.b64encode(payload).decode('utf-8')

class GoogleKMS:
    def __init__(self,gcp_login:GCPLogin, key_id:str):
        self.gcp_login=gcp_login
        self.info = {
            "key_id":key_id,
            "project_id": None,
            "location": None,
            "keyring": None,
            "key": None,
            "version": None
        }

        self.retrieve_key_info()

    def get_project_id(self)->str:
        return self.info["project_id"]
    
    def get_key_id(self)->str:
        return self.info['key_id']

    def retrieve_key_info(self):
        parts=self.info['key_id'].split("/")
        self.info["project_id"]=parts[ parts.index('projects') + 1]
        self.info["location"]=parts[ parts.index('locations') + 1]
        self.info["keyring"]=parts[ parts.index('keyRings') + 1]
        self.info["key"]=parts[ parts.index('cryptoKeys') + 1]
        self.info["version"]=parts[ parts.index('cryptoKeyVersions') + 1]
        
        
    def __str__(self):
        return f"GoogleKMS: {self.info}"
    
    def sign_string(self,string:str):
        url =f"https://cloudkms.googleapis.com/v1/projects/{self.info['project_id']}/locations/{self.info['location']}/keyRings/{self.info['keyring']}/cryptoKeys/{self.info['key']}/cryptoKeyVersions/{self.info['version']}:asymmetricSign?alt=json"
        headers = {
            "x-goog-user-project": f"{self.info['project_id']}"
        }
        data=json.dumps({"digest":{"sha512":string}})
        response = self.gcp_login.send_request(url=url, method="POST", headers=headers, data=data)
        
        if response['error'] or not response['data'] or  "signature" not in response['data'] :
            return None
        return response['data']['signature']



class GoogleBinaryAuthorizationAttestor:
    def __init__(self,gcp_login:GCPLogin, name:str, kms_key:GoogleKMS=None, project_id:str=None):
        self.gcp_login=gcp_login
        self.kms_key=kms_key
        self.info = {
            "project_id": project_id,
            "name": name,
            "note_reference": None,
            "note_id": None
        }

        if not project_id:
            self.info['project_id']=gcp_login.get_project_id()
        
        attestor_retrieved_info=self.retrieve_attestor_info()
        if not kms_key:
            key_id=attestor_retrieved_info['userOwnedGrafeasNote']['publicKeys'][0]['id']
            self.kms_key=GoogleKMS(gcp_login=gcp_login,key_id=key_id)

        self.info['note_reference']=attestor_retrieved_info['userOwnedGrafeasNote']['noteReference']
        self.info['note_id']=self.info['note_reference'].split("/")[-1]

    def get_kms_key(self)->str:
        return self.kms_key

    def get_project_id(self)->str:
        return self.info["project_id"]

    def __str__(self):
        return f"GoogleBinaryAuthorizationAttestor: {self.key_info} {self.attestor_info}"
    
    def retrieve_attestor_info(self):
        logging.info("Retriving attestor informations")
        attestor_name=self.info['name']
        project_id=self.info['project_id']
        url =f"https://binaryauthorization.googleapis.com/v1/projects/{project_id}/attestors/{attestor_name}"
        headers = {
            "x-goog-user-project": f"{project_id}"
        }
        response = self.gcp_login.send_request(url=url, method="GET", headers=headers, data=None)
        if response['data']:
            return response['data']
        else:
            raise Exception("It was not possible to retrieve attestor informations")
    
    def generate_attestation_payload(self,fully_qualified_digest:str,serialized_payload:str,payload_signature:str)->bytes:
        payload = {
        "resourceUri": fully_qualified_digest,
        "note_name": self.info['note_reference'],
        "attestation": {
            "serialized_payload": serialized_payload,
            "signatures": [
                {
                    "public_key_id": self.kms_key.get_key_id(),
                    "signature": payload_signature
                }]
            }
        }
        str_payload=json.dumps(payload,indent=None)
        return str_payload.encode('utf-8')
    
    def upload_attestation(self,fully_qualified_digest:str,serialized_payload:str,payload_signature:str):
        attestation_payload=self.generate_attestation_payload(fully_qualified_digest,serialized_payload,payload_signature)
        url =f"https://containeranalysis.googleapis.com/v1/projects/{self.info['project_id']}/occurrences/"
        headers = {
            "x-goog-user-project": f"{self.info['project_id']}"
        }
        data=attestation_payload
        response = self.gcp_login.send_request(url=url, method="POST", headers=headers, data=data)
        if response['data']:
            return response['data']
        elif response['error'] and "Conflict for url" in response['error']:
            logging.warning("Attestation not uploaded: Conflict for the attestation url, are you trying to upload the same attestation twice?")
        return None
    
    def get_image_attestation(self,fully_qualified_digest)->dict:
        attestor_name=self.info["name"]
        attestor_project_id=self.info["project_id"]
        cmd = f"gcloud container binauthz attestations list --artifact-url=\"{fully_qualified_digest}\" --attestor=\"{attestor_name}\" --attestor-project=\"{attestor_project_id}\" --format=json"
        stdout, stderr = self.gcp_login.execute_shell_command(cmd,timeout=2)

        if stderr is None:
            result=stdout.strip()
            result_json=None
            try:
                result_json=json.loads(result)
                signatures=[]
                for attestation_obj in result_json:
                    attestation=attestation_obj["attestation"]["signatures"]
                    for signature in attestation:
                        signatures.append(signature)
                if len(signatures)>0:
                    logging.info(f"Image: {fully_qualified_digest}")
                    for signature in signatures:
                        logging.info(f"signed by publicKeyId: {signature['publicKeyId']}")
                        logging.info(f"with signature: {signature['signature']}")
                return signatures

            except:
                logging.info(f"Image not signed:{fully_qualified_digest}")
        else:
            logging.debug(f"Error: {stderr}")
            logging.critical(f"Failed to verify image {fully_qualified_digest}")

        return None

def get_command_line_args():
    parser = argparse.ArgumentParser(description='Process command line arguments.')

    # Define the expected command-line arguments
    parser.add_argument('--image-path', type=str, help='us-docker.pkg.dev/<projectid>/<repositoryname>/[image_name@sha256<image_digest> or image_name:<image_tag>]')
    parser.add_argument('--source-image-path', type=str, help='<docker_repository>/[image_name@sha256<image_digest> or image_name:<image_tag>]')
    parser.add_argument('--destination-artifact-repository', type=str, help='us-docker.pkg.dev/<projectid>/<repositoryname>')
    parser.add_argument('--attestor-project-name', type=str, default=None, help='<projectid>')
    parser.add_argument('--attestor-name', type=str, default='tag-attestor', help='<tag-attestor-name>')
    parser.add_argument('--attestor-key-id', type=str, default=None, help='//cloudkms.googleapis.com/v1/projects/<projectid>/locations/<location>/keyRings/<keyring>/cryptoKeys/<key>/cryptoKeyVersions/1')
    parser.add_argument('--signer-logging-level', type=str, default='INFO', choices=['CRITICAL', 'FATAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'], help='CRITICAL|FATAL|ERROR|WARNING|INFO|DEBUG')
    parser.add_argument('--command', type=str, default='sign', choices=['sign', 'verify', 'transfer', 'transfer-and-sign'], help='sign|verify|transfer|transfer-and-sign')
    parser.add_argument('--platform', type=str, default='linux/amd64', help='platform used for pulling images')
    
    args = parser.parse_args()

    return args



def sign_image(gcp_login:GCPLogin,image_path:str,attestor_name:str,attestor_project_id:str,attestor_key_id:str=None):
    
    try:
        pprint(image_path)
        gcp_artifactory_image=GoogleArtifactoryImage(gcp_login=gcp_login,image_path=image_path)
    except Exception as e:
        logging.critical(f"Image {image_path} not present remotely")
        return None

    if attestor_key_id:
        kms_key=GoogleKMS(gcp_login=gcp_login,key_id=attestor_key_id)
    else:
        kms_key=None
    
    gcp_attestor=GoogleBinaryAuthorizationAttestor(gcp_login,name=attestor_name,project_id=attestor_project_id,kms_key=kms_key)
    kms_key=gcp_attestor.get_kms_key()

    logging.info("Image signing ...")
    #------ Genereting payload ----------------------#
    logging.info("Generating docker_image_description in base64 of the docker_image_description_sha256")
    image_info=gcp_artifactory_image.get_base64_encoded_payload()
    image_info_sha256=gcp_artifactory_image.get_base64_encoded_payload_hash()
    
    #------ generate payload signature----------------------#
    logging.info("Calling google kms to sign image_description_payload sha256")
    image_info_sha256_signature=kms_key.sign_string(image_info_sha256)
    
    #------ Generate image attestation ----------------------#
    logging.info("Generate attestation to upload")
    attestation_payload=gcp_attestor.upload_attestation(fully_qualified_digest=gcp_artifactory_image.get_fully_qualified_digest(),serialized_payload=image_info,payload_signature=image_info_sha256_signature)
    logging.info("Process completed")
    return attestation_payload

def verify_image(gcp_login:GCPLogin,image_path:str,attestor_name:str,attestor_project_id:str):
    
    gcp_artifactory_image=GoogleArtifactoryImage(gcp_login=gcp_login,image_path=image_path)
    gcp_attestor=GoogleBinaryAuthorizationAttestor(gcp_login,name=attestor_name,project_id=attestor_project_id)
    kms_key=gcp_attestor.get_kms_key()


    logging.info("Image verification ...")
    fully_qualified_digest=gcp_artifactory_image.get_fully_qualified_digest()
    print(fully_qualified_digest)
    gcp_attestor.get_image_attestation(fully_qualified_digest)

def transfer(gcp_login:GCPLogin,source_image_path:str,destination_artifact_repository:str)->str:
    docker_image=DockerImage(gcp_login=gcp_login,image_path=source_image_path)
    destination_image_path=f"{destination_artifact_repository}/{docker_image.get_image_name()}:{docker_image.get_image_tag()}"
    image_pulled=docker_image.pull()
    if not image_pulled:
        return False
    try:
        #if raise exception, image does not exists remotely
        GoogleArtifactoryImage(gcp_login=gcp_login,image_path=destination_image_path)
    except:
        pass
        #in his case image does not exists yet remotely
        docker_image.push(destination_image_path)
    
    return destination_image_path   


def set_logging_level(logging_level):
    logging_level_options={
        "CRITICAL":logging.CRITICAL,
        "ERROR":logging.ERROR,
        "WARNING":logging.WARNING,
        "INFO":logging.INFO,
        "DEBUG":logging.DEBUG
    }
    logging.root.setLevel(logging_level_options[logging_level])

def main():
    #------ Extract arguments/setup variables ----------------------#
    env_variables=get_command_line_args()
    
    logging_level=env_variables.signer_logging_level
    attestor_project_id=env_variables.attestor_project_name
    attestor_name=env_variables.attestor_name
    image_path=env_variables.image_path
    attestor_key_id=env_variables.attestor_key_id
    source_image_path=env_variables.source_image_path
    command=env_variables.command
    destination_artifact_repository=env_variables.destination_artifact_repository
    current_user_email=None

    set_logging_level(logging_level)

    gcp_login=GCPLogin()

    if command == "sign":
        sign_image(gcp_login=gcp_login,image_path=image_path,attestor_name=attestor_name,attestor_project_id=attestor_project_id,attestor_key_id=attestor_key_id)
    elif command == "verify":
        verify_image(gcp_login=gcp_login,image_path=image_path,attestor_name=attestor_name,attestor_project_id=attestor_project_id)
    elif command == "transfer":
        image_path=transfer(gcp_login=gcp_login,source_image_path=source_image_path,destination_artifact_repository=destination_artifact_repository)
        if not image_path:
            logging.critical(f"It was not possible to transfer {source_image_path} to {destination_artifact_repository}")      
    elif command == "transfer-and-sign":
        image_path=transfer(gcp_login=gcp_login,source_image_path=source_image_path,destination_artifact_repository=destination_artifact_repository)
        if not image_path:
            logging.critical(f"It was not possible to transfer {source_image_path} to {destination_artifact_repository}")
            return
        attestation_payload=sign_image(gcp_login=gcp_login,image_path=image_path,attestor_name=attestor_name,attestor_project_id=attestor_project_id,attestor_key_id=attestor_key_id)
        if not attestation_payload:
            return
        verify_image(gcp_login=gcp_login,image_path=image_path,attestor_name=attestor_name,attestor_project_id=attestor_project_id)
    else:
        logging.critical(f"command {command} not found")

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',stream=sys.stdout,level=logging.INFO)
    main()

