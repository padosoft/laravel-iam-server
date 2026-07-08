<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Padosoft\Iam\Http\Admin\Support\AdminContext;
use Padosoft\Iam\Http\Admin\Support\ApiProblemException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Idempotency-Key per le mutazioni Admin API (doc 16 §6). Sulle scritture (POST/PUT/PATCH/DELETE)
 * richiede l'header `Idempotency-Key`; alla prima richiesta esegue e salva l'esito, ai retry con la
 * stessa chiave rigioca la risposta salvata (at-most-once sugli effetti). La chiave è isolata per
 * attore; se riusata con un payload diverso → 422 (errore client). Una chiave "in volo" → 409.
 */
final class IdempotencyKey
{
    private const TABLE = 'iam_idempotency_keys';

    private const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (!in_array($request->getMethod(), self::WRITE_METHODS, true)) {
            return $next($request);
        }

        $key = $request->headers->get('Idempotency-Key');
        if (!is_string($key) || $key === '') {
            throw ApiProblemException::unprocessable('Header Idempotency-Key obbligatorio per le mutazioni.');
        }

        $context = $request->attributes->get('iam_admin_context');
        $actorRef = $context instanceof AdminContext ? $context->actorRef() : 'anonymous';
        $requestHash = hash('sha256', $request->getMethod().'|'.$request->getPathInfo().'|'.$request->getContent());

        // Claim atomico della chiave: insertOrIgnore vince la corsa; se la riga esisteva già
        // gestiamo replay/conflitto leggendola.
        $claimed = DB::table(self::TABLE)->insertOrIgnore([
            'id' => (string) Str::ulid(),
            'actor_ref' => $actorRef,
            'idempotency_key' => $key,
            'method' => $request->getMethod(),
            'path' => $request->getPathInfo(),
            'request_hash' => $requestHash,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        if ($claimed === 0) {
            return $this->replayOrConflict($actorRef, $key, $requestHash);
        }

        $response = $next($request);

        // Salva l'esito solo se NON è un 5xx: gli errori server restano riprovabili con la stessa chiave.
        if ($response->getStatusCode() < 500) {
            $body = $response->getContent();
            DB::table(self::TABLE)
                ->where('actor_ref', $actorRef)->where('idempotency_key', $key)
                ->update([
                    'response_status' => $response->getStatusCode(),
                    // IAM-08: never persist one-time secrets in clear. Some admin mutations (rotate-secret,
                    // manifest apply) return a freshly minted client_secret in the body; the caller already
                    // received the real value in the live response above — the STORED/replayed copy is
                    // redacted so the idempotency table never becomes a recoverable cleartext credential store.
                    'response_body' => $body === false ? null : $this->redactSecrets($body),
                    'updated_at' => now(),
                ]);
        } else {
            // 5xx: rilascia il claim così un retry può rieseguire.
            DB::table(self::TABLE)->where('actor_ref', $actorRef)->where('idempotency_key', $key)->delete();
        }

        return $response;
    }

    private function replayOrConflict(string $actorRef, string $key, string $requestHash): Response
    {
        $row = DB::table(self::TABLE)
            ->where('actor_ref', $actorRef)->where('idempotency_key', $key)
            ->first();

        if ($row === null) {
            // Il claim è stato rilasciato (5xx) tra l'insertOrIgnore e la lettura: chiedi il retry.
            throw ApiProblemException::conflict('Richiesta idempotente in corso: riprova.');
        }

        if (($row->request_hash ?? null) !== $requestHash) {
            throw ApiProblemException::unprocessable('Idempotency-Key già usata con un payload diverso.');
        }

        $status = $row->response_status ?? null;
        if (!is_numeric($status)) {
            // Claim presente ma esito non ancora salvato: richiesta concorrente in volo OPPURE claim
            // orfano (processo morto tra claim ed esito). Oltre un timeout lo consideriamo orfano e lo
            // rilasciamo, così i retry non restano bloccati in 409 per sempre (no deadlock idempotente).
            // IAM-41: elapsed time must be a POSITIVE magnitude. Carbon::diffInSeconds is signed, so the
            // old `now()->diffInSeconds(createdAt)` was negative for a past timestamp and the orphan release
            // never fired (keys stranded at 409). Compare timestamps directly for an unambiguous elapsed.
            $createdAt = $row->created_at ?? null;
            $age = is_string($createdAt) ? now()->getTimestamp() - Carbon::parse($createdAt)->getTimestamp() : 0;
            if ($age >= $this->inFlightTimeout()) {
                DB::table(self::TABLE)->where('actor_ref', $actorRef)->where('idempotency_key', $key)->delete();
            }

            throw ApiProblemException::conflict('Richiesta idempotente in corso: riprova.');
        }

        $body = is_string($row->response_body ?? null) ? $row->response_body : '';

        return new JsonResponse(
            json_decode($body, true),
            (int) $status,
            ['Content-Type' => 'application/json', 'Idempotency-Replayed' => 'true'],
        );
    }

    /**
     * IAM-08: redige i campi segreti da un body JSON prima di persisterlo (replay idempotente). I
     * segreti one-time (client_secret, secret, access_token, refresh_token, secret_previous) non devono
     * mai finire in chiaro nello store. Un body non-JSON viene restituito invariato (le risposte admin
     * sono JSON; un formato ignoto non è un vettore noto di segreti).
     */
    private function redactSecrets(string $body): string
    {
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            return $body;
        }
        $redacted = $this->redactArray($decoded);

        return json_encode($redacted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: $body;
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private function redactArray(array $data): array
    {
        $secretKeys = ['client_secret', 'secret', 'secret_previous', 'access_token', 'refresh_token', 'private_key', 'password'];
        foreach ($data as $k => $v) {
            if (is_string($k) && in_array(strtolower($k), $secretKeys, true) && $v !== null) {
                $data[$k] = '[REDACTED]';
            } elseif (is_array($v)) {
                $data[$k] = $this->redactArray($v);
            }
        }

        return $data;
    }

    /** Secondi oltre i quali un claim senza esito è considerato orfano (default 60s). */
    private function inFlightTimeout(): int
    {
        $value = config('iam.admin.idempotency_timeout', 60);

        return is_int($value) && $value > 0 ? $value : 60;
    }
}
