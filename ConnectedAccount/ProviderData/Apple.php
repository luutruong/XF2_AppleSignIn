<?php

namespace Truonglv\AppleSignIn\ConnectedAccount\ProviderData;

use XF\ConnectedAccount\ProviderData\AbstractProviderData;

class Apple extends AbstractProviderData
{
    /**
     * @return string
     */
    public function getDefaultEndpoint()
    {
        return '';
    }

    /**
     * @return string
     */
    public function getProviderKey()
    {
        return '';
    }
}
