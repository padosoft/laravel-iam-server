<?php

declare(strict_types=1);

namespace Padosoft\Iam;

use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Crypto\KeyProvider;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Domain\Authorization\Pdp\NativeSqlEngine;
use Padosoft\Iam\Domain\Crypto\LocalKeyProvider;
use Padosoft\Iam\Domain\Crypto\LocalSecretCipher;
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

    public function packageRegistered(): void
    {
        // M2: PDP engine nativo (RBAC+ABAC, deny-overrides) come AuthorizationEngine.
        $this->app->bind(AuthorizationEngine::class, NativeSqlEngine::class);

        // M3: crypto (envelope encryption + crypto-shredding).
        $this->app->singleton(KeyProvider::class, fn (): LocalKeyProvider => new LocalKeyProvider($this->resolveKek()));
        $this->app->singleton(SecretCipher::class, fn (): LocalSecretCipher => new LocalSecretCipher($this->app->make(KeyProvider::class)));
    }

    /** Risolve la KEK locale (32 byte) da config; in dev/test la deriva da APP_KEY se assente. */
    private function resolveKek(): string
    {
        $configured = config('iam.crypto.kek');
        if (is_string($configured) && $configured !== '') {
            $raw = base64_decode($configured, true);
            if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                throw new \RuntimeException('iam.crypto.kek non valida: attesa chiave base64 di '.SODIUM_CRYPTO_SECRETBOX_KEYBYTES.' byte.');
            }

            return $raw;
        }

        // Fallback dev: KEK derivata da APP_KEY. In PRODUZIONE usa una KEK esplicita / KMS (M3 AWS).
        $appKey = config('app.key');

        return sodium_crypto_generichash(is_string($appKey) ? $appKey : '', '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    public function packageBooted(): void
    {
        // M1: migration canoniche (identity, org, membership, grant).
        // Il server possiede lo schema; disattivabile via config (iam.run_migrations).
        if ((bool) config('iam.run_migrations', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }
    }
}
