# ebay-oauth-token

- [Installation](#installation)
- [Usage](#usage)

## Installation

``` sh
composer require w3lifer/ebay-oauth-token
```

## Usage

``` php
use w3lifer\EbayOAuthToken;

$ebayOAuthToken =
    new EbayOAuthToken([
        'absPathToFileToStoreUserAccessRefreshToken' => __DIR__ . '/ebay-oath-refresh-token', // Required, string
        'credentials' => EBAY_CREDENTIALS['production']['credentials'], // Required, array
        'ruName' => EBAY_CREDENTIALS['production']['ruName'], // Required, string
        // An authorization code is not required to generate an application access token.
        // It is used once to a store long-lived refresh token when we generate a user access token.
        // https://developer.ebay.com/api-docs/static/oauth-tokens.html
        // 'authorizationCode' => '<authorization-code>', // Optional
        'prod' => true, // Optional ("sandbox" environment will be used by default)  
    ]);

$applicationAccessToken = $ebayOAuthToken->getApplicationAccessToken();

$userAccessToken = $ebayOAuthToken->getUserAccessToken();
```
