<?php

declare(strict_types=1);

namespace Tests;

use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;
use Padosoft\Iam\IamServiceProvider;

abstract class TestCase extends Orchestra
{
    /**
     * Il server è il pacchetto core: PDP, identity, OAuth, audit, governance.
     *
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            IamServiceProvider::class,
        ];
    }

    /** @param  Application  $app */
    protected function defineEnvironment($app): void
    {
        // APP_KEY di test: testbench non la imposta; serve per cifratura.
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));

        // Lock atomici richiedono uno store con LockProvider.
        $app['config']->set('cache.default', 'array');

        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);

        // KEK di test (32 byte, base64) per il layer crypto del server.
        $app['config']->set('iam.crypto.kek', base64_encode(str_repeat('K', 32)));

        // openssl.cnf di Herd (Windows) per la keygen EC; su Linux/CI non serve.
        $cnf = (getenv('USERPROFILE') ?: '').'/.config/herd/bin/php85/extras/ssl/openssl.cnf';
        if (is_file($cnf)) {
            $app['config']->set('iam.crypto.openssl_config', $cnf);
        }
    }
}
