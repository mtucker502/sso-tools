# sso-tools

Easily access pages protected with various SSO implementations.

Simply create an instance of the class and then call the `get()` or `post()` methods. Login is handled for you.

## Credentials

Credentials can be provided in two ways:

1. **Environment variables** - Set `SSO_USER` and `SSO_PASSWORD`
2. **Direct initialization** - Pass a dictionary with `sso_user` and `sso_password` keys

Direct credentials take precedence over environment variables. You can also mix both methods (e.g., user from direct, password from environment).

## Example

Using environment variables:

```bash
export SSO_USER="user@example.com"
export SSO_PASSWORD="password"
```

```python
from sso_tools import AzureSSO

my_site = AzureSSO(
    verify=False,
    no_script=[
        'Since your browser does not support JavaScript',
        'Script is disabled. Click Submit to continue'
    ]
)

my_site.post(url, data=data)
```

Using direct credentials:

```python
from sso_tools import AzureSSO

my_site = AzureSSO(
    sso_credentials={'sso_user': 'user@example.com', 'sso_password': 'password'},
    verify=False,
    no_script=[
        'Since your browser does not support JavaScript',
        'Script is disabled. Click Submit to continue'
    ]
)

my_site.post(url, data=data)
```
