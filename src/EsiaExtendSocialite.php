<?php

namespace SocialiteProviders\Esia;

use SocialiteProviders\Manager\SocialiteWasCalled;

class EsiaExtendSocialite
{
    /**
     * Execute the provider.
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('esia', __NAMESPACE__.'\Provider');
    }
}
