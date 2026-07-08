<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Identity;

use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthRefreshToken;

/**
 * Contenimento immediato di un soggetto (IAM-05, doc 10 §7). Quando un utente è sospeso/off-boarded, la
 * revoca deve avere effetto SUBITO, non alla scadenza naturale di sessioni e token: qui si revocano in
 * un colpo solo tutte le sessioni server-side e tutti gli access/refresh token OAuth vivi dell'utente.
 *
 * È il braccio "containment". L'enforcement (il PDP nega un utente non attivo) vive nel NativeSqlEngine:
 * i due insieme fanno sì che sospendere un account tolga davvero l'accesso, invece di flippare solo un flag.
 */
final class SubjectRevoker
{
    public function __construct(private readonly SessionRegistry $sessions) {}

    /**
     * Revoca ogni sessione e ogni token OAuth vivo dell'utente. Idempotente: rieseguirlo non fa danni.
     */
    public function revokeUserAccess(string $userId, string $reason): void
    {
        $this->sessions->revokeAllForSubject(new SubjectRef('user', $userId), $reason);

        // Gli access token portano user_id; i refresh token si collegano tramite access_token_jti. Revoco
        // prima raccogliendo i jti vivi, poi cifro entrambe le tabelle (l'ordine non crea finestre: un
        // refresh su un access appena revocato fallisce comunque il replay-detection del RefreshTokenGrant).
        $jtis = OauthAccessToken::query()
            ->where('user_id', $userId)
            ->where('revoked', false)
            ->pluck('jti')
            ->all();

        OauthAccessToken::query()
            ->where('user_id', $userId)
            ->where('revoked', false)
            ->update(['revoked' => true]);

        if ($jtis !== []) {
            OauthRefreshToken::query()
                ->whereIn('access_token_jti', $jtis)
                ->where('revoked', false)
                ->update(['revoked' => true]);
        }
    }
}
