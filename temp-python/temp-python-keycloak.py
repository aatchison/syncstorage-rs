import requests
import jwt
import json
from base64 import b64decode

# public-client: get token for user using password grant_type
print("get public client token")

keycloak_server_url = "http://localhost:7080/realms/sync/protocol/openid-connect/token"

data = {
    'grant_type': 'password',
    'client_id': 'public-client',
    'scope': 'email openid',
    'username': 'test@test.com',
    'password': '1234'
}


response = requests.post(keycloak_server_url, data)
print(f"GET status code: {response.status_code}")
# print(f"GET response content: {response.json()}")
print(f"GET response content access_token: {response.json()["access_token"]}")
public_client_jwt = response.json()["access_token"]





# confidential-client: get token for user using password grant_type

print("get private client token")


# confidential_client_secret = "YcdeiCc742lOk17poGhWT51GTAWMnQMr"
# keycloak_server_url = "http://localhost:7080/realms/sync/protocol/openid-connect/token"

# data = {
#     'grant_type': 'client_credentials',
#     'client_id': 'confidential-client',
#     'scope': 'openid',
#     'client_secret': confidential_client_secret
# }

# response = requests.post(keycloak_server_url, data)
# print(f"GET status code: {response.status_code}")
# # print(f"GET response content: {response.json()}")
# # print(f"GET response content id_token: {response.json()["id_token"]}")

# print(f"GET response content access_token: {response.json()["access_token"]}")
# private_client_jwt = response.json()["access_token"]



# get certs

confidential_client_secret = "YcdeiCc742lOk17poGhWT51GTAWMnQMr"
keycloak_server_url = "http://localhost:7080/realms/sync/protocol/openid-connect/certs"

data = {
    'grant_type': 'client_credentials',
    'client_id': 'confidential-client',
    'scope': 'openid',
    'client_secret': confidential_client_secret
}

response = requests.get(keycloak_server_url, data)
print(f"GET status code: {response.status_code}")
# print(f"GET response content: {json.dumps(response.json(), indent=4)}")
# print(f"GET response content id_token: {response.json()["id_token"]}")

# decode token and validate signature

jwks_client = jwt.PyJWKClient(keycloak_server_url)
signing_key = jwks_client.get_signing_key_from_jwt(public_client_jwt)
decoded_token = jwt.decode(public_client_jwt, signing_key.key, algorithms=["RS256"], audience="account")
print(decoded_token)

# print("decode public client wt token")
# try:
#     decoded_token = jwt.decode(public_client_jwt, secret, "algorithms=["RSA-OAEP",])
#     print(decoded_token)
# except jwt.ExpiredSignatureError:
#     print("Token has expired")
# except jwt.InvalidTokenError:
#     print("Invalid token")
# except Exception as e:
#     print(f"An error occurred: {e}")

# don't verify signature
# try:
#     decoded_token = jwt.decode(public_client_jwt, options={"verify_signature": False})
#     print(decoded_token)
# except jwt.ExpiredSignatureError:
#     print("Token has expired")
# except jwt.InvalidTokenError:
#     print("Invalid token")
# except Exception as e:
#     print(f"An error occurred: {e}")