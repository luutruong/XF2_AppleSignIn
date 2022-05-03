<?php

namespace Truonglv\AppleSignIn;

use XF\AddOn\AbstractSetup;
use XF\AddOn\StepRunnerInstallTrait;
use XF\AddOn\StepRunnerUpgradeTrait;
use XF\AddOn\StepRunnerUninstallTrait;
use XF\Entity\ConnectedAccountProvider;
use Truonglv\AppleSignIn\DevHelper\SetupTrait;

class Setup extends AbstractSetup
{
    use SetupTrait;
    use StepRunnerInstallTrait;
    use StepRunnerUpgradeTrait;
    use StepRunnerUninstallTrait;

    public function installStep1(): void
    {
        /** @var ConnectedAccountProvider $provider */
        $provider = $this->app->em()->create('XF:ConnectedAccountProvider');
        $provider->provider_id = 'asi_apple';
        $provider->provider_class = 'Truonglv\AppleSignIn:Provider\Apple';
        $provider->display_order = 9000;
        $provider->save();
    }

    public function uninstallStep1(): void
    {
        $provider = $this->app->em()->find('XF:ConnectedAccountProvider', 'asi_apple');
        if ($provider !== null) {
            $provider->delete();
        }
    }
}
