<?php

namespace Truonglv\AppleSignIn\ConnectedAccount\ProviderData;

use XF;
use stdClass;
use function time;
use LogicException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use InvalidArgumentException;
use CoderCat\JWKToPEM\JWKConverter;
use XF\ConnectedAccount\ProviderData\AbstractProviderData;

class Apple extends AbstractProviderData
{
    const CACHE_KEY_GET_USER = 'appleSignIn_getUser';
    const APPLE_ISSUER = 'https://appleid.apple.com';

    const APPLE_API_AUTH_KEYS = 'https://appleid.apple.com/auth/keys';

    /**
     * @return string
     */
    public function getDefaultEndpoint()
    {
        throw new LogicException('Not supported');
    }

    /**
     * @return string
     */
    public function getProviderKey()
    {
        $user = $this->getUser();

        return $user->sub;
    }

    public function getEmail(): string
    {
        $user = $this->getUser();
        if (!isset($user->email)) {
            throw new LogicException('Apple did not give user email');
        }

        return $user->email;
    }

    /**
     * @param mixed $key
     * @param mixed $method
     * @param mixed $endpoint
     * @return mixed
     */
    public function requestFromEndpoint($key = null, $method = 'GET', $endpoint = null)
    {
        // not supported
        return null;
    }

    protected function getAuthKeys(): array
    {
        $cacheData = XF::app()->simpleCache()->getValue(
            'Truonglv/AppleSignIn',
            'authKeys'
        );
        if (is_array($cacheData) &&
            isset($cacheData['expires']) &&
            $cacheData['expires'] >= time()
        ) {
            return $cacheData['keys'];
        }

        $client = XF::app()->http()->client();
        $response = $client->get(static::APPLE_API_AUTH_KEYS);

        $json = json_decode($response->getBody()->getContents(), true);
        if (!isset($json['keys'])) {
            throw new InvalidArgumentException('Cannot fetch authKeys');
        }
        XF::app()->simpleCache()->setValue(
            'Truonglv/AppleSignIn',
            'authKeys',
            [
                'expires' => time() + 86400,
                'keys' => $json['keys'],
            ]
        );

        return $json['keys'];
    }

    protected function getUser(): stdClass
    {
        if (isset($this->cache[static::CACHE_KEY_GET_USER])) {
            return $this->cache[static::CACHE_KEY_GET_USER];
        }

        $tokenProvider = $this->storageState->getProviderToken();
        if ($tokenProvider === false) {
            throw new InvalidArgumentException('no token passed in provider');
        }
        $token = $tokenProvider->getAccessToken();
        $this->assertValidJwtToken($token);

        list($header, , ) = \explode('.', $token);
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
            throw new InvalidArgumentException('cannot find auth key: ' . $header->kid);
        }

        $jwkConverter = new JWKConverter();
        $publicKey = $jwkConverter->toPEM($foundAuthKey);

        $decoded = JWT::decode($token, [
            $header->kid => new Key($publicKey, $header->alg)
        ]);

        if ($decoded->iss !== static::APPLE_ISSUER) {
            throw new InvalidArgumentException('invalid issuer: ' . $decoded->iss);
        }

        $this->storeInCache(static::CACHE_KEY_GET_USER, $decoded);

        return $decoded;
    }

    protected function assertValidJwtToken(string $token): void
    {
        if (strlen($token) === 0) {
            throw new InvalidArgumentException('token is empty');
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('invalid token format');
        }
    }
}
