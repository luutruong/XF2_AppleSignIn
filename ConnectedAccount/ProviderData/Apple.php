<?php

namespace Truonglv\AppleSignIn\ConnectedAccount\ProviderData;

use CoderCat\JWKToPEM\JWKConverter;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use XF\ConnectedAccount\ProviderData\AbstractProviderData;

class Apple extends AbstractProviderData
{
    /**
     * @return string
     */
    public function getDefaultEndpoint()
    {
        throw new \LogicException('Not supported');
    }

    /**
     * @return string
     */
    public function getProviderKey()
    {
        $user = $this->getUser();
        if ($user === null) {
            throw new \LogicException('Cannot decode user');
        }

        return $user->sub;
    }

    public function getEmail(): string
    {
        $user = $this->getUser();
        if ($user === null) {
            throw new \LogicException('Cannot decode user');
        }

        return $user->email;
    }

    public function requestFromEndpoint($key = null, $method = 'GET', $endpoint = null)
    {
        throw new \LogicException('Not supported');
    }

    protected function getAuthKeys(): array
    {
        $authKeys = \XF::app()->simpleCache()->getValue(
            'Truonglv/AppleSignIn',
            'authKeys'
        );
        if (is_array($authKeys)) {
            return $authKeys;
        }

        $client = \XF::app()->http()->client();
        $response = $client->get('https://appleid.apple.com/auth/keys');

        $json = json_decode($response->getBody()->getContents(), true);
        if (!isset($json['keys'])) {
            throw new \InvalidArgumentException('Cannot fetch authKeys');
        }
        \XF::app()->simpleCache()->setValue(
            'Truonglv/AppleSignIn',
            'authKeys',
            $json['keys']
        );

        return $json['keys'];
    }

    protected function getUser(): ?\stdClass
    {
        if (isset($this->cache[__METHOD__])) {
            return $this->cache[__METHOD__];
        }

        $tokenProvider = $this->storageState->getProviderToken();
        if ($tokenProvider === false) {
            return null;
        }
        $token = $tokenProvider->getAccessToken();

        if (strlen($token) === 0) {
            return null;
        }

        if (strpos($token, '.') === false) {
            return null;
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        $header = array_shift($parts);
        $header = JWT::jsonDecode(JWT::urlsafeB64Decode($header));

        $authKeys = $this->getAuthKeys();
        $foundAuthKey = null;
        foreach ($authKeys as $authKey) {
            if ($authKey['kid'] === $header->kid) {
                $foundAuthKey = $authKey;

                break;
            }
        }

        if ($foundAuthKey === null) {
            return null;
        }

        $jwkConverter = new JWKConverter();

        try {
            $publicKey = $jwkConverter->toPEM($foundAuthKey);
        } catch (\Throwable $e) {
            \XF::logException($e, false, '[tl] Sign in with Apple: ');

            return null;
        }

        try {
            $decoded = JWT::decode($token, [
                $header->kid => new Key($publicKey, $header->alg)
            ]);
        } catch (\Exception $e) {
            \XF::logException($e, false, '[tl] Sign in with Apple: ');

            return null;
        }

        if ($decoded->iss !== 'https://appleid.apple.com') {
            return null;
        }

        $this->storeInCache(__METHOD__, $decoded);

        return $decoded;
    }
}
