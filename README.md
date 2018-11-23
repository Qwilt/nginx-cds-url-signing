# nginx-cds-url-signing
Nginx module that implements Cisco's CDS Url Signing algorithm

# Description:

The Nginx CDS Url Signing module provides functionality for CDS implementation of url signing.
It can validate the request url using CDS logic, or sign a user given url with it.
For more info on CDS url signing and an eample python script for signing - see Cisco's documentation at:
https://www.cisco.com/c/en/us/td/docs/video/cds/cda/is/2_0/developer/guide/URLsigning.html

# Installation:

You'll need to re-compile Nginx from source to include this module or link it dynamically.
Modify your compile of Nginx by adding the following directive (modified to suit your path of course):

Static module (built-in nginx binary)

    ./configure --add-module=/absolute/path/to/nginx-cds-url-signing

Dynamic nginx module `ngx_http_cds_url_signing_module.so` module

    ./configure --add-dynamic-module=/absolute/path/to/nginx-cds-url-signing

Build Nginx

    make
    make install

# Usage:


```nginx
Syntax: cds_key <key owner> <key number> <key string>;
Default: none
Context: http, server, location
```
Add a key for signing/validation.  
Multiple keys can be added this way.


```nginx
Syntax: cds_exclude_domain on | off;
Default: cds_exclude_domain off;
Context: http, server, location
```
Sets if domain should be part of validated/signed data.  
By default signed data is decided by the sign version.  
However when this flag is set to "on" the entire scheme and domain are stripped before validation/signing.


```nginx
Syntax: cds_validate_expiration on | off;
Default: cds_validate_expiration on;
Context: http, server, location
```
Should validate url expiration time in ET arg.  
Value in `ET` is epoc time in seconds. If that time is lower than current epoc time in seconds validation fails.  
Validation is performed by checking the value of `$cds_validate` variable.


```nginx
Syntax: cds_validate_client_ip on | off;
Default: cds_validate_client_ip on;
Context: http, server, location
```
Should validate client ip address against `CIP` arg or not.  
Note that if `CIP` value matches cds_validate_client_ip_to_ignore value client ip validation is disabled as well.  
Validation is performed by checking the value of `$cds_validate` variable.


```nginx
Syntax: cds_validate_client_ip_to_ignore address;
Default: none;
Context: http, server, location
```
When this ip address matches the value of `CIP' arg, disable client ip validation for that transaction.  
Validation is performed by checking the value of `$cds_validate` variable.


```nginx
Syntax: cds_validate_host_override host;
Default: none;
Context: http, server, location
```
When set, this host is used instead of the original host when performing the validation. Input may contain variables.  
Validation is performed by checking the value of `$cds_validate` variable.



```nginx
Syntax: cds_sign_url URL;
Default: none
Context: http, server, location
```
Url to sign on.
Must be a full url, including scheme. Input may contain variables.  
Variable `$cds_signed_url` will hold the final signed url, based on this url and other signing directives.


```nginx
Syntax: cds_sign_client_ip address;
Default: none;
Context: http, server, location
```
Client ip to use in `CIP` arg when signing the url provided by `cds_sign_url`.  
Input may contain variables.


```nginx
Syntax: cds_sign_mimic_request on | off;
Default: cds_sign_mimic_request on;
Context: http, server, location
```
When enabled - if signing of a url is performed after a successful validation of the request url, the values of args `SIGV`, `ET`, `KO`, `KN` are taken from request url instead of the configuration.


```nginx
Syntax: cds_sign_version 0 | 1 | 2;
Default: cds_sign_version 2;
Context: http, server, location
```
Set the sign version for the signed url.  
This is equal to the values acceptable by the `SIGV` arg.  
`0` - sign entire url with md5. `SIGV` is not added to the url.  
`1` - sign entire url with sha1. `SIGV=1` is added to the url.  
`2` - sign entire url with sha1, skipping the scheme (i.e. 'http'/'https' string only). `SIGV=2` is added to the url.


```nginx
Syntax: cds_sign_key_owner number;
Default: cds_sign_key_owner 0;
Context: http, server, location
```
Key owner index to use when looking for a key to sign the url with.  
Will also be set in `KO` arg in signed url.


```nginx
Syntax: cds_sign_key_number number;
Default: cds_sign_key_number 0;
Context: http, server, location
```
Key number index to use when looking for a key to sign the url with.  
Will also be set in `KN` arg in signed url.


```nginx
Syntax: cds_sign_expiration_sec sec;
Default: cds_sign_expiration_sec 120s;
Context: http, server, location
```
Delta (in seconds) to set as expiration time in signed url.  
This value will be added to current epoc time in seconds and will be set in `ET` arg in the signed url.


# Embedded Variables:


```nginx
$cds_validate
```
Validates the request is correctly signed according to the logic explained above.  
Returns "1" if signature matches.  
Returns "" if signature mismatch.  
Returns "0" if signature match but client ip doesn't or the url expired.


```nginx
$cds_validate_is_exp_ok
```
This variable works only after calling `$cds_validate` (else it will always return "").  
Returns "1" if the url expiration time validation passed, "" otherwise.


```nginx
$cds_validate_is_ip_ok
```
This variable works only after calling `$cds_validate` (else it will always return "").  
Returns "1" if the client ip validation passed, "" otherwise.


```nginx
$cds_signed_url
```
Signs the configured url according to the signing configuration as described above.  
Returns the full signed url (including scheme, host, path).


```nginx
$cds_signed_path
```
This variable works only after calling `$cds_signed_url` (else it will always return "").  
Returns the path part of the signed url. i.e. same as `$cds_signed_url` but without the shceme and host.


```nginx
$cds_signed_token
```
This variable works only after calling `$cds_signed_url` (else it will always return "").  
Returns the signature itself of the signed url. i.e. the value if `US`.



# Examples:

Configuration example for validation:

```nginx
location ~ ^/files/ {
    # Key's for validation (or signing).
    cds_key 0 0 "00000000";
    cds_key 0 1 "11111111";
    cds_key 0 2 "22222222";

    # Validate using entire request url (honoring SIGV=2 in request).
    cds_exclude_domain off;

    # Validate the CIP and ET args in request
    cds_validate_client_ip on;
    cds_validate_expiration on;

    # Reject the requst if cds validation fails
    if ($cds_validate != "1") {
        return 403;
    }

    return 200 "You got served";
}
```



Configuration example for signing:

```nginx
location ~ ^/fetch/ {
    # Key's for signing (or validation).
    cds_key 1 1 "11111111";

    # Validate using entire request url (honoring SIGV=2 in request).
    cds_exclude_domain off;

    # Url to sign on
    cds_sign_url "$scheme://www.fetch-host.com$request_uri";

    # Signing directives
    cds_sign_client_ip $server_addr;
    cds_sign_version 2;
    cds_sign_key_owner 1;
    cds_sign_key_number 1;
    cds_sign_expiration_sec 60s;

    proxy_pass $cds_signed_url;
}
```



Application side can use Cisco's python example script for generating signed urls:
https://www.cisco.com/c/en/us/td/docs/video/cds/cda/is/2_0/developer/guide/URLsigning.html#wp1003509



