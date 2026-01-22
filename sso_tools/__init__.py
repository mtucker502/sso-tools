import logging
import os
import requests
import urllib3
from bs4 import BeautifulSoup
import re

log = logging.getLogger(__name__)

__all__ = ['BaseSSO', 'AzureSSO', 'OktaSSO']


class BaseSSO():
    """Base class for building sub classes for specific SSO implementations."""

    def __init__(self,
                 sso_credentials=None,        # dictionary containing 'sso_user' and 'sso_password'
                 verify=True,
                 no_script=[],                # list of strings to match for no JavaScript detection
                 ):
        # Build credentials from passed values or fall back to environment variables
        env_user = os.environ.get('SSO_USER')
        env_password = os.environ.get('SSO_PASSWORD')

        if sso_credentials is None:
            sso_credentials = {}

        self.sso_credentials = {
            'sso_user': sso_credentials.get('sso_user') or env_user,
            'sso_password': sso_credentials.get('sso_password') or env_password,
        }
        self.no_script = no_script
        self.logged_in = False
        
        log.info('Initializing requests session')
        self.headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux i686; rv:7.0.1) Gecko/20100101 Firefox/7.0.1'}
        self.session = requests.session()
        self.session.headers.update(self.headers)
        log.info('Initialization complete')

        if not verify:
            self.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            self.verify = verify

    def login(self, url, **kwargs):
        """Override this method with implementation specific method"""
        pass

    def build_csrf_vars(self, response):
        """ Takes response body as input and returns all hidden input fields/values as a dictionary"""

        log.info('CSRF: Building svars database')
        c = response.content
        soup = BeautifulSoup(c, 'lxml')
        svars = {}
        for var in soup.findAll('input', type="hidden"):
            svars[var['name']] = var['value']
            log.debug('CSRF: {}'.format(var))
        log.debug('CSRF: Returning csrf list: {}'.format(svars))

        return svars

    def get(self, url, **kwargs):
        """Method utilizes existing requests session for repeated GET requests"""
        if self.logged_in:
            log.info('GET request to {}'.format(url))
            return self.handle_http_error(self.session.get(url, verify=self.verify, **kwargs))
        else:
            return self.login(url=url, method='GET', verify=self.verify, **kwargs)

    def post(self, url, data=None, **kwargs):
        """Method utilizes existing requests session for repeated POST requests"""
        if self.logged_in:
            log.info('POST request to {}'.format(url))
            return self.handle_http_error(self.session.post(url, data=data, **kwargs))
        else:
            return self.login(url=url, method='POST', data=data, verify=self.verify, **kwargs)

    def handle_http_error(self, response):
        """Method which checks for OK status codes or otherwise raises exception."""
        if response.status_code != requests.codes.ok:
            log.error('Received HTTP {0} when attempting to access {1}'.format(response.status_code, response.url))
            Exception('Received HTTP {0} when attempting to access {1}'.format(response.status_code, response.url))

        # loop until we exhaust list
        # if we match then break out of while loop

        response = self.handle_no_script(response)

        return response

    def handle_no_script(self, response):
        """Method which recursively tries to circumvent no javascript detection. Uses self.no_script list as keyword search."""
        for no_script in self.no_script:
            if no_script in response.text:
                log.warning('No javascript detection triggered! Must use interim page')
                svars = self.build_csrf_vars(response)
                soup = BeautifulSoup(response.content, 'lxml')
                forms = soup.find('form', method=re.compile('post', re.IGNORECASE))
                if forms:
                    postURL = soup.find('form', method=re.compile('post', re.IGNORECASE)).get('action')
                    log.warning('Interim POST URL {}'.format(postURL))
                    # use self.session.post here to prevent login loop with self.post
                    response = self.session.post(postURL, data=svars)
                    return self.handle_no_script(response)

        return response


# Import submodules for convenience
from sso_tools.azure_sso import AzureSSO
from sso_tools.okta_sso import OktaSSO
