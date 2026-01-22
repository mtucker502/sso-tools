import logging
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode
from sso_tools import BaseSSO


log = logging.getLogger(__name__)


class OktaSSO(BaseSSO):
    """Easily access pages protected with Okta OAuth/OIDC SSO"""

    def login(self, url, method=None, **kwargs):
        """Attempt to login. A protected URL is required here to catch the redirect to Okta."""

        # We need to use self.session instead of self.get and self.post since both get/post methods
        # check for login and will end in a loop

        log.info('Starting Okta OAuth login flow')

        # Step 1: Make initial request to protected URL (don't follow redirects)
        if method == 'GET':
            r = self.session.get(url, allow_redirects=False, **kwargs)
        elif method == 'POST':
            r = self.session.post(url, allow_redirects=False, **kwargs)

        # Step 2: Follow redirects to find the Okta authorization URL
        okta_auth_url = self._find_okta_auth_url(r, **kwargs)

        if not okta_auth_url:
            raise Exception('Could not find Okta authorization URL in redirect chain')

        log.info('Found Okta authorization URL')

        # Step 3: Extract OAuth parameters and Okta base URL
        parsed_url = urlparse(okta_auth_url)
        okta_base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        oauth_params = parse_qs(parsed_url.query)

        # Flatten single-value lists from parse_qs
        oauth_params = {k: v[0] if len(v) == 1 else v for k, v in oauth_params.items()}

        log.debug(f'Okta base URL: {okta_base_url}')
        log.debug(f'OAuth params: {oauth_params}')

        # Step 4: Authenticate with Okta's authn API to get session token
        session_token = self._authenticate_with_okta(okta_base_url)

        # Step 5: Exchange session token for authorization code via authorize endpoint
        # Append sessionToken to the authorize URL and follow redirects
        auth_params = {
            'client_id': oauth_params.get('client_id'),
            'response_type': oauth_params.get('response_type', 'code'),
            'scope': oauth_params.get('scope', 'openid profile email'),
            'redirect_uri': oauth_params.get('redirect_uri'),
            'state': oauth_params.get('state', ''),
            'nonce': oauth_params.get('nonce', ''),
            'sessionToken': session_token
        }

        # Remove None values
        auth_params = {k: v for k, v in auth_params.items() if v is not None}

        authorize_url = f"{okta_base_url}{parsed_url.path}?{urlencode(auth_params)}"

        log.info('Exchanging session token for authorization code')
        r = self.session.get(authorize_url, verify=self.verify, allow_redirects=True)
        r = self.handle_http_error(r)

        log.info('Successfully logged in via Okta OAuth')
        self.logged_in = True

        return r

    def _find_okta_auth_url(self, response, **kwargs):
        """Follow redirects to find the Okta authorization URL"""
        max_redirects = 10
        current_response = response

        for _ in range(max_redirects):
            if current_response.status_code not in (301, 302, 303, 307, 308):
                # Check if we're on an Okta page by looking at the URL or content
                if '/oauth2/' in current_response.url and '/authorize' in current_response.url:
                    return current_response.url
                # Not a redirect and not an Okta authorize URL
                break

            redirect_url = current_response.headers.get('Location')
            if not redirect_url:
                break

            # Check if this is the Okta authorization URL
            if '/oauth2/' in redirect_url and '/authorize' in redirect_url:
                return redirect_url

            # Follow the redirect
            log.debug(f'Following redirect to: {redirect_url}')
            current_response = self.session.get(redirect_url, allow_redirects=False, verify=self.verify)

        # If we didn't find it in redirects, check if the final URL contains Okta auth
        if '/oauth2/' in current_response.url and '/authorize' in current_response.url:
            return current_response.url

        return None

    def _authenticate_with_okta(self, okta_base_url):
        """Authenticate with Okta's authn API and return the session token"""

        authn_url = f"{okta_base_url}/api/v1/authn"

        auth_payload = {
            'username': self.sso_credentials['sso_user'],
            'password': self.sso_credentials['sso_password'],
            'options': {
                'multiOptionalFactorEnroll': False,
                'warnBeforePasswordExpired': False
            }
        }

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        log.info('Authenticating with Okta authn API')
        r = self.session.post(authn_url, json=auth_payload, headers=headers, verify=self.verify)

        if r.status_code != 200:
            log.error(f'Okta authentication failed with status {r.status_code}')
            try:
                error_data = r.json()
                error_msg = error_data.get('errorSummary', 'Unknown error')
                log.error(f'Okta error: {error_msg}')
                raise Exception(f'Okta authentication failed: {error_msg}')
            except json.JSONDecodeError:
                raise Exception(f'Okta authentication failed with status {r.status_code}')

        auth_response = r.json()
        status = auth_response.get('status')

        if status == 'SUCCESS':
            session_token = auth_response.get('sessionToken')
            if not session_token:
                raise Exception('Okta authentication succeeded but no session token returned')
            log.info('Successfully obtained Okta session token')
            return session_token

        elif status == 'MFA_REQUIRED':
            # Handle MFA if configured
            raise Exception('MFA is required but not yet supported. Please configure MFA handling.')

        elif status == 'MFA_ENROLL':
            raise Exception('MFA enrollment is required. Please complete enrollment in a browser first.')

        elif status == 'LOCKED_OUT':
            raise Exception('Account is locked out. Please contact your administrator.')

        elif status == 'PASSWORD_EXPIRED':
            raise Exception('Password has expired. Please reset your password.')

        else:
            raise Exception(f'Unexpected Okta authentication status: {status}')

    def get_okta_config(self, response):
        """Extract Okta configuration from the login page JavaScript"""

        log.info('Extracting Okta configuration from response')
        content = response.text

        # Look for oktaData configuration object
        okta_data_match = re.search(r'var\s+oktaData\s*=\s*({.*?});', content, re.DOTALL)
        if okta_data_match:
            try:
                # Clean up the JavaScript object to make it valid JSON
                okta_data_str = okta_data_match.group(1)
                # This is a simplified extraction - real parsing might need more work
                return json.loads(okta_data_str)
            except json.JSONDecodeError:
                log.warning('Could not parse oktaData as JSON')

        # Alternative: look for signIn configuration
        signin_config_match = re.search(r'OktaSignIn\(\s*({.*?})\s*\)', content, re.DOTALL)
        if signin_config_match:
            try:
                return json.loads(signin_config_match.group(1))
            except json.JSONDecodeError:
                log.warning('Could not parse OktaSignIn config as JSON')

        return {}
