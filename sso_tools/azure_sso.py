import logging
from bs4 import BeautifulSoup
import re
import json
from sso_tools import BaseSSO


log = logging.getLogger(__name__)


class AzureSSO(BaseSSO):
    """Easily access pages protected with Oracle Access Management SSO"""

    def login(self, url, method=None, **kwargs):
        """Attempt to login. A protected URL is required here to catch the redirect."""

        # We need to use self.session instead of self.get and self.post since both get/post methods
        #  check for login and will end in a loop
        if method == 'GET':
            r = self.handle_http_error(self.session.get(url, **kwargs))
        elif method == 'POST':
            r = self.handle_http_error(self.session.post(url, **kwargs))
        
        config = self.get_azure_config(r)
        svars = self.build_csrf_vars(r) 

        svars['login'] = self.sso_credentials['sso_user']#.replace('@', '%40')
        svars['loginfmt'] = self.sso_credentials['sso_user']#.replace('@', '%40')
        svars['passwd'] = self.sso_credentials['sso_password']

        svars['canary'] = config['canary']
        svars['ctx'] = config['sCtx']

        svars['hpgrequestid'] = r.headers.get('x-ms-request-id')
        svars[config['sFTName']] = config['sFT']

        
        svars['i13'] = 0
        svars['type'] = 11
        svars['LoginOptions'] = 3
        svars['lrt'] = None
        svars['lrtPartition'] = None
        svars['hisRegion'] = None
        svars['hisScaleUnit'] = None
        svars['ps'] = 2
        svars['psRNGCDefaultType'] = None
        svars['psRNGCEntropy'] = None
        svars['psRNGCSLK'] = None
        svars['PPSX'] = None
        svars['NewUser'] = 1
        svars['FoundMSAs'] = None
        svars['fspost'] = 0
        svars['i21'] = 0
        svars['CookieDisclosure'] = 0
        svars['IsFidoSupported'] = 1
        svars['isSignupPost'] = 0
        svars['i2'] = 1
        svars['i17'] = None
        svars['i18'] = None
        svars['i19'] = 249023 #FIXME: Is this dependent on the Org?


        log.info('POSTing credentials to SSO')
        self.sso_url = config['urlResume'].split('resume')[0] + 'login'
        r = self.handle_http_error(self.session.post(self.sso_url, data=svars))
        
        log.info('Successfully logged in')
        self.logged_in = True

        return r

    def get_azure_config(self, response):
        """ Takes response body as input and returns all Azure config options as a dictionary"""
        log.info('Config: Building svars database')
        c = response.content
        soup = BeautifulSoup(c, 'html.parser')
        script =  soup.script.get_text()
        config = script.split('$Config=')[1].split(';\n//]]')[0]

        return json.loads(config)
