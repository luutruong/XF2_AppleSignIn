<?php

namespace Truonglv\AppleSignIn\ConnectedAccount\Provider;

use XF;
use XF\Http\Request;
use Firebase\JWT\JWT;
use OAuth\OAuth2\Token\StdOAuth2Token;
use XF\Entity\ConnectedAccountProvider;
use XF\ConnectedAccount\Storage\StorageState;
use XF\ConnectedAccount\Provider\AbstractProvider;

class Apple extends AbstractProvider
{
    /**
     * @return string
     */
    public function getOAuthServiceName()
    {
        return 'Truonglv\AppleSignIn:Service\Apple';
    }

    /**
     * @return string
     */
    public function getProviderDataClass()
    {
        return 'Truonglv\AppleSignIn:ProviderData\Apple';
    }

    /**
     * @return array
     */
    public function getDefaultOptions()
    {
        return [
            'client_id' => '',
            'private_key' => '',
            'team_id' => '',
            'key_id' => '',
        ];
    }

    /**
     * @param ConnectedAccountProvider $provider
     * @param mixed $redirectUri
     * @return array
     */
    public function getOAuthConfig(ConnectedAccountProvider $provider, $redirectUri = null)
    {
        return [
            'key' => $provider->options['client_id'],
            'secret' => $this->getClientSecret($provider->options),
            'redirect' => $redirectUri === null ? $this->getRedirectUri($provider) : $redirectUri,
            'scopes' => ['email', 'name']
        ];
    }

    /**
     * @return array
     */
    public function getAdditionalAuthParams()
    {
        return [
            'response_mode' => 'form_post',
            'response_type' => 'code id_token',
        ];
    }

    /**
     * @return string
     */
    public function getTitle()
    {
        return '[tl] Sign in with Apple';
    }

    protected function getClientSecret(array $options): string
    {
        return JWT::encode([
            'iss' => $options['key_id'],
            'iat' => time(),
            'exp' => time() + 3600,
            'aud' => 'https://appleid.apple.com',
            'sub' => $options['key_id']
        ], $options['private_key'], 'ES256', $options['key_id']);
    }

    /**
     * @param StorageState $storageState
     * @param Request $request
     * @param mixed $error
     * @param mixed $skipStoredToken
     * @return mixed
     */
    public function requestProviderToken(StorageState $storageState, Request $request, &$error = null, $skipStoredToken = false)
    {
        $version = $this->getOAuthVersion();
        $skipStoredToken = (bool) $skipStoredToken;
        if (!$skipStoredToken) {
            $token = $storageState->getProviderToken();
            if ($token && $version == 2) {
                return $token;
            }
        }

        if ($request->filter('error', 'str') == 'access_denied' || $request->filter('denied', 'str')) {
            $error = XF::phraseDeferred('you_did_not_grant_permission_to_access_connected_account');

            return false;
        }

        $token = $request->filter('id_token', 'str');
        if ($token === '') {
            $error = XF::phraseDeferred('error_occurred_while_connecting_with_x', ['provider' => $this->getTitle()]);

            return false;
        }

        $stdToken = new StdOAuth2Token();
        $stdToken->setAccessToken($token);
        $stdToken->setEndOfLife(StdOAuth2Token::EOL_UNKNOWN);

        $storageState->storeToken($stdToken);

        return $stdToken;
    }
}
