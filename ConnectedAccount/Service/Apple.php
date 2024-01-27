<?php

namespace Truonglv\AppleSignIn\ConnectedAccount\Service;

use LogicException;
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
        throw new LogicException('Not supported');
    }

    /**
     * @param array $additionalParameters
     * @return \OAuth\Common\Http\Uri\UriInterface
     */
    public function getAuthorizationUri(array $additionalParameters = [])
    {
        /** @var mixed $credentials */
        $credentials = $this->credentials;

        $parameters = array_merge(
            $additionalParameters,
            [
                'type'          => 'web_server',
                'client_id'     => $credentials->getConsumerId(),
                'redirect_uri'  => $credentials->getCallbackUrl(),
            ]
        );

        $parameters['scope'] = implode($this->getScopesDelimiter(), $this->scopes);

        // Build the url
        $url = clone $this->getAuthorizationEndpoint();
        foreach ($parameters as $key => $val) {
            $url->addToQuery($key, $val);
        }

        return $url;
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
