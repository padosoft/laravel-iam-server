<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use Illuminate\Http\JsonResponse;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;

/**
 * JWKS endpoint (doc 13 §7/§8): GET /.well-known/jwks.json.
 * Espone le chiavi pubbliche attive + in overlap, così i client verificano i JWT (access/id token).
 */
final class JwksController
{
    public function __construct(private readonly TokenSigner $signer) {}

    public function jwks(): JsonResponse
    {
        return response()->json(['keys' => $this->signer->jwks()])
            ->header('Cache-Control', 'public, max-age=300');
    }
}
