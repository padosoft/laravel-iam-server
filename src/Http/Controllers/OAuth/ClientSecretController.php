<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Repositories\ClientRepository;

/**
 * Self-fetch del secret ruotato (doc 13 §4.2). Un client con auto-rotazione, durante il grace, chiama
 * questo endpoint autenticandosi col PROPRIO secret ancora valido (quello corrente o il precedente in
 * grace) e riceve il NUOVO secret in chiaro, per poi fare hot-swap. Solo il client legittimo — che
 * possiede un secret valido — può ottenerlo: `validateClient` è il gate (nessun bearer/PDP qui, è
 * autenticazione di client, non di utente). Il nuovo secret è custodito cifrato-at-rest fino al pickup.
 */
final class ClientSecretController
{
    public function __construct(private readonly ClientRepository $clients) {}

    public function current(Request $request): JsonResponse
    {
        if (config('iam.oauth.client_selffetch', true) !== true) {
            return response()->json(['error' => 'not_found'], 404);
        }

        [$clientId, $clientSecret] = $this->credentials($request);
        // Gate: deve autenticarsi col proprio secret (corrente O precedente-in-grace). Fail-closed.
        if ($clientId === null || !$this->clients->validateClient($clientId, $clientSecret, null)) {
            return response()->json(['error' => 'invalid_client'], 401);
        }

        $client = OauthClient::query()->where('client_id', $clientId)->whereNull('revoked_at')->first();
        $pending = $client?->pendingSecret();
        if ($client === null || $pending === null) {
            // Niente da ritirare (nessuna rotazione pendente).
            return response()->json(['rotated' => false]);
        }

        return response()->json([
            'rotated' => true,
            'client_id' => $clientId,
            'client_secret' => $pending,
            'grace_until' => $client->secret_previous_expires_at?->toIso8601String(),
        ]);
    }

    /**
     * @return array{0: ?string, 1: ?string}
     */
    private function credentials(Request $request): array
    {
        // HTTP Basic (client_secret_basic) preferito; fallback su body (client_secret_post).
        $user = $request->getUser();
        if (is_string($user) && $user !== '') {
            $pass = $request->getPassword();

            return [$user, is_string($pass) ? $pass : null];
        }
        $id = $request->input('client_id');
        $secret = $request->input('client_secret');

        return [is_string($id) && $id !== '' ? $id : null, is_string($secret) ? $secret : null];
    }
}
