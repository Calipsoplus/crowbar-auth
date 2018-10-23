## To install on Ubuntu/Debian:
apt-get install libxml2-dev libxmlsec1-dev xmlsec1 sqlite3<br>

## Python installation:
pip3 install -r requirements.txt

## Configuration:
SECRET_KEY=  
SAML_METADATA_URL=  url_for_saml2_authenticator  
FERNET_KEY=  fernet_key_value_must_be_same_as_crowbar_guacamole_and_web_  
COOKIE_AUTH=  name_of_cookie_with_auth_value  
COOKIE_USER=  name_of_cookie_with_user_name_value  
CROWBAR_WEB_IP= ip_address_of_crowbar_angular_app

When configuring these values, all values must be surrounded with "" e.g CROWBAR_WEB_IP="http://localhost:4200"
## To run:
python3 app.py
