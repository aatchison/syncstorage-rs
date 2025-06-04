# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
from base64 import urlsafe_b64encode as b64encode
import binascii
import json
import os
import math
import time
import urllib.parse as urlparse
import requests

from sqlalchemy import create_engine
from tokenlib.utils import decode_token_bytes
from webtest import TestApp

DEFAULT_OAUTH_SCOPE = 'https://identity.mozilla.com/apps/oldsync'


class TestCase:
    FXA_EMAIL_DOMAIN = 'api-accounts.stage.mozaws.net'
    FXA_METRICS_HASH_SECRET = os.environ.get("SYNC_MASTER_SECRET", 'secret0')
    NODE_ID = 800
    NODE_URL = 'https://example.com'
    TOKEN_SIGNING_SECRET = os.environ.get("SYNC_MASTER_SECRET", 'secret0')
    TOKENSERVER_HOST = os.environ['TOKENSERVER_HOST']

    @classmethod
    def setUpClass(cls):
        cls._build_auth_headers = cls._build_oauth_headers

    def setUp(self):
        engine = create_engine(os.environ['SYNC_TOKENSERVER__DATABASE_URL'])
        self.database = engine. \
            execution_options(isolation_level='AUTOCOMMIT'). \
            connect()

        host_url = urlparse.urlparse(self.TOKENSERVER_HOST)
        self.app = TestApp(self.TOKENSERVER_HOST, extra_environ={
            'HTTP_HOST': host_url.netloc,
            'wsgi.url_scheme': host_url.scheme or 'http',
            'SERVER_NAME': host_url.hostname,
            'REMOTE_ADDR': '127.0.0.1',
            'SCRIPT_NAME': host_url.path,
        })

        # Start each test with a blank slate.
        cursor = self._execute_sql(('DELETE FROM users'), ())
        cursor.close()

        cursor = self._execute_sql(('DELETE FROM nodes'), ())
        cursor.close()

        self.service_id = self._add_service('sync-1.5', r'{node}/1.5/{uid}')

        # Ensure we have a node with enough capacity to run the tests.
        self._add_node(capacity=100, node=self.NODE_URL, id=self.NODE_ID)

    def tearDown(self):
        # And clean up at the end, for good measure.
        cursor = self._execute_sql(('DELETE FROM users'), ())
        cursor.close()

        cursor = self._execute_sql(('DELETE FROM nodes'), ())
        cursor.close()

        cursor = self._execute_sql(('DELETE FROM services'), ())
        cursor.close()

        self.database.close()

    def _get_keycloak_token(self):
        """Get a real JWT token from Keycloak for testing using client credentials"""
        # Check if we're using OIDC/Keycloak
        oauth_provider_type = os.environ.get('SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE', 'fxa')
        if oauth_provider_type != 'oidc':
            return None
            
        # Get Keycloak server URL from environment
        keycloak_base_url = os.environ.get('SYNC_TOKENSERVER__OIDC_ISSUER_URL', 
                                         os.environ.get('SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL'))
        if not keycloak_base_url:
            return None
            
        # Use the Keycloak URL as-is when running in Docker, or replace with localhost for local testing
        # Check if we're running in Docker by looking for the KEYCLOAK_URL environment variable
        if os.environ.get('KEYCLOAK_URL'):
            # Running in Docker - use the internal hostname
            token_url = f"{keycloak_base_url}/protocol/openid-connect/token"
        else:
            # Running locally - replace with localhost
            keycloak_base_url = keycloak_base_url.replace('keycloak:7080', 'localhost:7080')
            token_url = f"{keycloak_base_url}/protocol/openid-connect/token"
        
        # Use confidential client credentials
        confidential_client_secret = "YcdeiCc742lOk17poGhWT51GTAWMnQMr"
        
        try:
            data = {
                'grant_type': 'client_credentials',
                'client_id': 'confidential-client',
                'scope': f'openid {DEFAULT_OAUTH_SCOPE}',
                'client_secret': confidential_client_secret
            }
            
            response = requests.post(token_url, data=data, timeout=10)
            
            if response.status_code == 200:
                token = response.json().get('access_token')
                return token
            else:
                print(f"Failed to get Keycloak token: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"Error getting Keycloak token: {e}")
            return None

    def _build_oauth_headers(self, generation=None, user='test',
                             keys_changed_at=None, client_state=None,
                             status=200, **additional_headers):
        # Try to get a real JWT token from Keycloak first
        real_token = self._get_keycloak_token()
        
        if real_token:
            # Use real JWT token from Keycloak
            headers = {}
            headers['Authorization'] = f'Bearer {real_token}'
            if client_state:
                client_state = binascii.unhexlify(client_state)
                client_state = b64encode(client_state).strip(b'=').decode('utf-8')
                headers['X-KeyID'] = '%s-%s' % (keys_changed_at, client_state)
            headers.update(additional_headers)
            return headers
        else:
            # Fallback to fake token for FxA or when Keycloak is not available
            claims = {
                'user': user,
                'generation': generation,
                'client_id': 'fake client id',
                'scope': [DEFAULT_OAUTH_SCOPE],
            }

            if generation is not None:
                claims['generation'] = generation

            body = {
                'body': claims,
                'status': status
            }

            headers = {}
            headers['Authorization'] = 'Bearer %s' % json.dumps(body)
            if client_state:
                client_state = binascii.unhexlify(client_state)
                client_state = b64encode(client_state).strip(b'=').decode('utf-8')
                headers['X-KeyID'] = '%s-%s' % (keys_changed_at, client_state)
            headers.update(additional_headers)

            return headers

    def _add_node(self, capacity=100, available=100, node=NODE_URL, id=None,
                  current_load=0, backoff=0, downed=0):
        query = 'INSERT INTO nodes (service, node, available, capacity, \
            current_load, backoff, downed'
        data = (self.service_id, node, available, capacity, current_load,
                backoff, downed)

        if id:
            query += ', id) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)'
            data += (id,)
        else:
            query += ') VALUES(%s, %s, %s, %s, %s, %s, %s)'

        cursor = self._execute_sql(query, data)
        cursor.close()

        return self._last_insert_id()

    def _get_node(self, id):
        query = 'SELECT * FROM nodes WHERE id=%s'
        cursor = self._execute_sql(query, (id,))
        (id, service, node, available, current_load, capacity, downed,
         backoff) = cursor.fetchone()
        cursor.close()

        return {
            'id': id,
            'service': service,
            'node': node,
            'available': available,
            'current_load': current_load,
            'capacity': capacity,
            'downed': downed,
            'backoff': backoff
        }

    def _last_insert_id(self):
        cursor = self._execute_sql('SELECT LAST_INSERT_ID()', ())
        (id,) = cursor.fetchone()
        cursor.close()

        return id

    def _add_service(self, service_name, pattern):
        query = 'INSERT INTO services (service, pattern) \
            VALUES(%s, %s)'
        cursor = self._execute_sql(query, (service_name, pattern))
        cursor.close()

        return self._last_insert_id()

    def _add_user(self, email=None, generation=1234, client_state='aaaa',
                  created_at=None, nodeid=NODE_ID, keys_changed_at=1234,
                  replaced_at=None):
        query = '''
            INSERT INTO users (service, email, generation, client_state, \
                created_at, nodeid, keys_changed_at, replaced_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        '''
        created_at = created_at or math.trunc(time.time() * 1000)
        
        # Use the correct email format based on OAuth provider
        if email is None:
            oauth_provider_type = os.environ.get('SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE', 'fxa')
            if oauth_provider_type == 'oidc':
                # When using Keycloak OIDC, the JWT subject is a UUID and email is constructed as {uuid}@{domain}
                # The service account UUID is fixed in our Keycloak configuration
                keycloak_service_account_uuid = '468ee2d8-047a-497a-9247-f8e7056608a6'
                email = f'{keycloak_service_account_uuid}@localhost'
            else:
                # Default FxA format
                email = 'test@%s' % self.FXA_EMAIL_DOMAIN
        
        cursor = self._execute_sql(query,
                                   (self.service_id,
                                    email,
                                    generation, client_state,
                                    created_at, nodeid, keys_changed_at,
                                    replaced_at))
        cursor.close()

        return self._last_insert_id()

    def _get_user(self, uid):
        query = 'SELECT * FROM users WHERE uid = %s'
        cursor = self._execute_sql(query, (uid,))

        (uid, service, email, generation, client_state, created_at,
         replaced_at, nodeid, keys_changed_at) = cursor.fetchone()
        cursor.close()

        return {
            'uid': uid,
            'service': service,
            'email': email,
            'generation': generation,
            'client_state': client_state,
            'created_at': created_at,
            'replaced_at': replaced_at,
            'nodeid': nodeid,
            'keys_changed_at': keys_changed_at
        }

    def _get_replaced_users(self, service_id, email):
        query = 'SELECT * FROM users WHERE service = %s AND email = %s AND \
            replaced_at IS NOT NULL'
        cursor = self._execute_sql(query, (service_id, email))

        users = []
        for user in cursor.fetchall():
            (uid, service, email, generation, client_state, created_at,
             replaced_at, nodeid, keys_changed_at) = user

            user_dict = {
                'uid': uid,
                'service': service,
                'email': email,
                'generation': generation,
                'client_state': client_state,
                'created_at': created_at,
                'replaced_at': replaced_at,
                'nodeid': nodeid,
                'keys_changed_at': keys_changed_at
            }
            users.append(user_dict)

        cursor.close()
        return users

    def _get_service_id(self, service):
        query = 'SELECT id FROM services WHERE service = %s'
        cursor = self._execute_sql(query, (service,))
        (service_id,) = cursor.fetchone()
        cursor.close()

        return service_id

    def _count_users(self):
        query = 'SELECT COUNT(DISTINCT(uid)) FROM users'
        cursor = self._execute_sql(query, ())
        (count,) = cursor.fetchone()
        cursor.close()

        return count

    def _execute_sql(self, query, args):
        cursor = self.database.execute(query, args)

        return cursor

    def unsafelyParseToken(self, token):
        # For testing purposes, don't check HMAC or anything...
        return json.loads(decode_token_bytes(token)[:-32].decode('utf8'))
