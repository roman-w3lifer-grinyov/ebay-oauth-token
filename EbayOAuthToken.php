<?php

namespace w3lifer;

use DTS\eBaySDK\OAuth\Services\OAuthService;
use DTS\eBaySDK\OAuth\Types\GetUserTokenRestRequest;
use DTS\eBaySDK\OAuth\Types\RefreshUserTokenRestRequest;
use Exception;

class EbayOAuthToken
{
    /**
     * @var string
     */
    private $absPathToFileToStoreUserAccessRefreshToken;

    /**
     * @var array
     */
    private $credentials;

    /**
     * @var string
     */
    private $ruName;

    /**
     * @var string
     */
    private $authorizationCode;

    /**
     * @var array
     * @see https://developer.ebay.com/my/keys See "OAuth Scopes" link.
     */
    private $scopeForClientCredentialGrantType = [
        'https://api.ebay.com/oauth/api_scope',
        'https://api.ebay.com/oauth/api_scope/buy.guest.order',
        'https://api.ebay.com/oauth/api_scope/buy.item.feed',
        'https://api.ebay.com/oauth/api_scope/buy.marketing',
        'https://api.ebay.com/oauth/api_scope/buy.product.feed',
        'https://api.ebay.com/oauth/api_scope/buy.marketplace.insights',
        'https://api.ebay.com/oauth/api_scope/buy.proxy.guest.order',
        'https://api.ebay.com/oauth/api_scope/sell.logistics.pudo',
    ];

    /**
     * @var array
     * @see https://developer.ebay.com/my/keys See "OAuth Scopes" link.
     */
    private $scopeForAuthorizationCodeGrantType = [
        'https://api.ebay.com/oauth/api_scope',
        'https://api.ebay.com/oauth/api_scope/buy.order.readonly',
        'https://api.ebay.com/oauth/api_scope/buy.guest.order',
        'https://api.ebay.com/oauth/api_scope/sell.marketing.readonly',
        'https://api.ebay.com/oauth/api_scope/sell.marketing',
        'https://api.ebay.com/oauth/api_scope/sell.inventory.readonly',
        'https://api.ebay.com/oauth/api_scope/sell.inventory',
        'https://api.ebay.com/oauth/api_scope/sell.account.readonly',
        'https://api.ebay.com/oauth/api_scope/sell.account',
        'https://api.ebay.com/oauth/api_scope/sell.fulfillment.readonly',
        'https://api.ebay.com/oauth/api_scope/sell.fulfillment',
        'https://api.ebay.com/oauth/api_scope/sell.analytics.readonly',
        'https://api.ebay.com/oauth/api_scope/sell.marketplace.insights.readonly',
        'https://api.ebay.com/oauth/api_scope/commerce.catalog.readonly',
        'https://api.ebay.com/oauth/api_scope/buy.shopping.cart',
        'https://api.ebay.com/oauth/api_scope/buy.offer.auction',
    ];

    /**
     * @var bool
     */
    private $prod;

    /**
     * @var bool
     */
    private $sandbox;

    /**
     * @var bool
     */
    private $debug;

    /**
     * @var string
     */
    private $applicationAccessToken;

    /**
     * @var string
     */
    private $userAccessToken;

    /**
     * @param array $config
     * @throws \Exception
     */
    public function __construct($config = [])
    {
        if (empty($config['absPathToFileToStoreUserAccessRefreshToken'])) {
            throw new Exception('You must specify "absPathToFileToStoreUserAccessRefreshToken"');
        }
        $this->absPathToFileToStoreUserAccessRefreshToken = $config['absPathToFileToStoreUserAccessRefreshToken'];

        if (
            empty($config['credentials']['appId']) ||
            empty($config['credentials']['devId']) ||
            empty($config['credentials']['certId'])
        ) {
            throw new Exception(
                'You must specify "credentials", which is an array consisting of "appId", "devId" and "certId" elements'
            );
        }
        $this->credentials = $config['credentials'];

        if (empty($config['ruName'])) {
            throw new Exception('You must specify "ruName"');
        }
        $this->ruName = $config['ruName'];

        $this->authorizationCode =
            !empty($config['authorizationCode'])
                ? $config['authorizationCode']
                : '';

        if (!empty($config['scopeForAuthorizationCodeGrantType'])) {
            $this->scopeForAuthorizationCodeGrantType =
                $config['scopeForAuthorizationCodeGrantType'];
        }

        if (!empty($config['scopeForClientCredentialGrantType'])) {
            $this->scopeForAuthorizationCodeGrantType =
                $config['scopeForClientCredentialGrantType'];
        }

        $this->prod = !empty($config['prod']) ? true : false;

        $this->sandbox = !$this->prod;

        $this->debug = !empty($config['debug']) ? true : false;
    }

    /**
     * Client credentials grant.
     * @param array $scope
     * @return array|string
     * @see https://developer.ebay.com/api-docs/static/oauth-token-types.html
     * @see https://github.com/davidtsadler/ebay-sdk-examples/blob/master/oauth-tokens/01-get-app-token.php
     */
    public function getApplicationAccessToken($scope = [])
    {
        if ($this->applicationAccessToken) {
            return $this->applicationAccessToken;
        }

        if (!$scope) {
            $scope = $this->scopeForClientCredentialGrantType;
        }

        $service = $this->getOAuthService($scope);

        $response = $service->getAppToken();

        if ($response->getStatusCode() !== 200) {
            return [$response->error . ': ' . $response->error_description];
        }

        return $this->applicationAccessToken = $response->access_token;
    }

    /**
     * Authorization code grant.
     * @param array $scope
     * @return array|string
     * @see https://developer.ebay.com/api-docs/static/oauth-token-types.html
     * @see https://github.com/davidtsadler/ebay-sdk-examples/blob/master/oauth-tokens/02-get-user-token.php
     */
    public function getUserAccessToken($scope = [])
    {
        if ($this->userAccessToken) {
            return $this->userAccessToken;
        }

        if (!$scope) {
            $scope = $this->scopeForAuthorizationCodeGrantType;
        }

        if ($this->authorizationCode) {

            $service = $this->getOAuthService($scope);

            $request = new GetUserTokenRestRequest();
            $request->code = $this->authorizationCode;

            $response = $service->getUserToken($request);

            if ($response->getStatusCode() !== 200) {
                return [$response->error => $response->error_description];
            }

            file_put_contents(
                $this->absPathToFileToStoreUserAccessRefreshToken,
                json_encode([
                    'validUntil' =>
                        time() + (int) $response->refresh_token_expires_in,
                    'refreshToken' => $response->refresh_token,
                ])
            );

            $this->userAccessToken = $response->access_token;

        } else {

            $this->userAccessToken = $this->refreshAndReturnUserAccessToken($scope);

        }

        return $this->userAccessToken;
    }

    /**
     * @param array $scope
     * @return array|string
     */
    private function refreshAndReturnUserAccessToken($scope)
    {
        $userAccessRefreshTokenData = $this->getUserAccessRefreshTokenFromStorage();

        if (!$userAccessRefreshTokenData) {
            return ['Refresh token does not exists'];
        } else if ($this->userAccessTokenIsExpired($userAccessRefreshTokenData)) {
            return ['Refresh token is expired'];
        }

        $service = $this->getOAuthService($scope);

        $request = new RefreshUserTokenRestRequest();

        $request->refresh_token = $userAccessRefreshTokenData['refreshToken'];

        $response = $service->refreshUserToken($request);

        if ($response->getStatusCode() !== 200) {
            return [$response->error . ': ' . $response->error_description];
        }

        return $response->access_token;
    }

    /**
     * @return array|string
     */
    private function getUserAccessRefreshTokenFromStorage()
    {
        if (file_exists($this->absPathToFileToStoreUserAccessRefreshToken)) {
            return
                json_decode(
                    file_get_contents(
                        $this->absPathToFileToStoreUserAccessRefreshToken
                    ),
                    true
                );
        }
        return '';
    }

    /**
     * @param array $userAccessRefreshTokenData
     * @return bool
     */
    private function userAccessTokenIsExpired($userAccessRefreshTokenData)
    {
        return time() > $userAccessRefreshTokenData['validUntil'];
    }

    /**
     * @param array $scope
     * @return \DTS\eBaySDK\OAuth\Services\OAuthService
     */
    private function getOAuthService($scope)
    {
        return
            new OAuthService([
                'credentials' => $this->credentials,
                'debug' => $this->debug,
                'ruName' => $this->ruName,
                'sandbox' => $this->sandbox,
                'scope' => $scope,
            ]);
    }
}
