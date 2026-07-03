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
        // Fail-closed: solo un client confidential può avere/ritirare un pending (defense-in-depth se un
        // client viene commutato a public con un pending residuo).
        $pending = $client !== null && $client->is_confidential ? $client->pendingSecret() : null;
        if ($client === null || $pending === null) {
            return $this->noStore(response()->json(['rotated' => false]));
        }

        $graceUntil = $client->secret_previous_expires_at?->toIso8601String();
        // Pickup ONE-TIME: azzeriamo subito il pending, così un vecchio secret trafugato non può "portarsi
        // avanti" prendendo il nuovo per tutta la finestra di grace — l'esposizione crolla a "prima che
        // l'app legittima l'abbia ritirato". Il vecchio resta valido per il resto del grace, quindi un
        // fetch-then-crash significa solo attendere la prossima rotazione (nessun downtime immediato).
        $client->clearPendingSecret();

        return $this->noStore(response()->json([
            'rotated' => true,
            'client_id' => $clientId,
            'client_secret' => $pending,
            'grace_until' => $graceUntil,
        ]));
    }

    /** RFC 6749 §5.1: nessuna cache su una risposta che porta credenziali. */
    private function noStore(JsonResponse $response): JsonResponse
    {
        return $response->header('Cache-Control', 'no-store')->header('Pragma', 'no-cache');
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
