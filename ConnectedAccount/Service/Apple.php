<?php

namespace Truonglv\AppleSignIn\ConnectedAccount\Service;

use OAuth\Common\Http\Uri\Uri;
use OAuth\OAuth2\Service\AbstractService;

class Apple extends AbstractService
{
    const SCOPE_EMAIL = 'email';
    const SCOPE_NAME = 'name';

    /**
     * @param mixed $responseBody
     * @return \OAuth\Common\Token\TokenInterface
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        dump($responseBody);
        die;
    }

    /**
     * @inheritDoc
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://appleid.apple.com/auth/authorize');
    }

    /**
     * @inheritDoc
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://appleid.apple.com/auth/token');
    }
}
