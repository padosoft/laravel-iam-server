<?php

declare(strict_types=1);

namespace Padosoft\Iam;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

/**
 * Service provider del server Laravel IAM.
 *
 * Si arricchisce milestone per milestone (vedi laravel-iam-docs/08 §8):
 *  - M1: ->hasMigrations([...]) identity/org/grants
 *  - M2: bind AuthorizationEngine (NativeSqlEngine) per il PDP
 *  - M3: bind KeyProvider/SecretCipher (LocalKeyProvider + AWS)
 *  - M4: rotte OAuth/OIDC (oauth.php) + discovery/jwks
 *  - M6: Application Registry + manifest commands
 *  - M7: audit/events/webhooks
 *  - M8: FeatureScope + IGA
 *  - M10: Admin API routes
 */
final class IamServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-iam-server')
            ->hasConfigFile('iam');
        // ->hasRoutes('api', 'oauth', 'auth')->hasCommands(...)  // M4+
    }

    public function packageBooted(): void
    {
        // M1: migration canoniche (identity, org, membership, grant)
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }
}
