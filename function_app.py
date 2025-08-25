import azure.functions as func
import logging
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os
import requests
import tempfile
import ssl
import json
from azure.storage.blob import BlobServiceClient
from datetime import datetime


credential = DefaultAzureCredential()
key_vault_url = os.environ.get("KEY_VAULT_URL")
secret_client = SecretClient(vault_url=key_vault_url, credential=credential)

def fix_pem_format(pem_string: str, pem_type: str) -> str:
    # Remove any leading/trailing whitespace
    pem_string = pem_string.strip()

    # Replace known PEM headers/footers with proper formatting
    header = f"-----BEGIN {pem_type}-----"
    footer = f"-----END {pem_type}-----"

    # Remove headers/footers to extract body
    body = pem_string.replace(header, "").replace(footer, "").replace(" ", "").replace("\n", "")

    # Wrap the body at 64 characters per line (standard PEM format)
    import textwrap
    body_wrapped = "\n".join(textwrap.wrap(body, 64))

    # Return fixed PEM string
    return f"{header}\n{body_wrapped}\n{footer}"


app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="transactions")
def transactions(req: func.HttpRequest) -> func.HttpResponse:

    logging.info('Python HTTP trigger function processed a request.')

    cert_pem = secret_client.get_secret("cert-pem").value
    key_pem = secret_client.get_secret("key-pem").value

    cert_pem = fix_pem_format(cert_pem, "CERTIFICATE")
    key_pem = fix_pem_format(key_pem, "PRIVATE KEY")

    # Now write the fixed PEMs to temp files
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w")
    cert_file.write(cert_pem)
    cert_file.close()
    cert_path = cert_file.name

    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w")
    key_file.write(key_pem)
    key_file.close()
    key_path = key_file.name


    account_id = os.environ.get("TELLER_ACCOUNT_ID")
    access_token = os.environ.get("TELLER_ACCESS_TOKEN")

    # from_id = 'txn_pfot8s9e1ma7j377n2001'

    params = {
        # "from_id": from_id,  # Optional: specify a transaction ID to fetch
        "count": 20
    }

    # Make the HTTPS request
    response = requests.get(
        f"https://api.teller.io/accounts/{account_id}/transactions",
        auth=(access_token, ""),                      # Basic Auth: token as username
        cert=(cert_path, key_path),                    # mTLS cert/key
        params=params                                  # Query parameters
    )

    # Output the results
    if response.ok:
        transactions = response.json()
        parsed_data = [
            {
                "amount": transaction.get("amount", 0),
                "description": transaction.get("description", ""),
                "date": transaction.get("date", ""),
                "id": transaction.get("id", ""),

            }
            for transaction in transactions
        ]
        json_array = json.dumps(parsed_data, indent=2)

        connection_string = os.environ["STORAGE_ACCOUNT_CONNECTION"]
        container_name = "bronze"
        # blob_name = "data_test.json"

        # Create filename with current date (e.g. data_2025-08-06.json)
        today_str = datetime.now().strftime("%Y-%m-%d")
        blob_name = f"transactions_{today_str}.json"  # path inside the container


        # Upload to Azure Blob Storage
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

        # Upload (overwrite if it exists)
        blob_client.upload_blob(json_array, overwrite=True)

    else:
        print("Error:", response.status_code)
        print(response.text)
    
    return func.HttpResponse("This HTTP triggered function executed successfully.")
