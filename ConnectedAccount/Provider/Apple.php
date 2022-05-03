<?php

namespace Truonglv\AppleSignIn\ConnectedAccount\Provider;

use Firebase\JWT\JWT;
use XF\ConnectedAccount\Storage\StorageState;
use XF\Entity\ConnectedAccountProvider;
use XF\ConnectedAccount\Provider\AbstractProvider;
use XF\Http\Request;

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
            'response_type' => 'code id_token',
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
        \XF::logError(__METHOD__);

        return parent::requestProviderToken($storageState, $request, $error, $skipStoredToken);
    }
}
