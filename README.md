# Two-factor authentication module for simpleSAMLphp using Google Authenticator

## Usage

 Configure it by adding an entry to `config/authsources.php` such as this:
 
 ```
       'authtfaga' => array(
           'authtfaga:authtfaga',
 
           'db.dsn' => 'mysql:host=db.example.com;port=3306;dbname=idpauthtfaga',
           'db.username' => 'simplesaml',
           'db.password' => 'bigsecret',
           'mainAuthSource' => 'ldap',
           'uidField' => 'uid',
           'totpIssuer' => 'dev_aai_teszt_IdP'
         ),
```
