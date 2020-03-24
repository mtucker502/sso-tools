# OAM_SSO

Easily access pages protected with various SSO implemntations

Simply create an instance of the class and then call the `get()` or `post()` methods. Login is handled for you.

## Example

```python
my_site = AzureSSO(
    sso_credentials=sso_credentials,
    verify=False,
    no_script = [
        'Since your browser does not support JavaScript',
        'Script is disabled. Click Submit to continue'
    ]
)

my_site.post(url, data=data)
```