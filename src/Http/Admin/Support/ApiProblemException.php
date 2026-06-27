<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Admin\Support;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Errore dell'Admin API in formato problem+json (RFC 9457, doc 16 §6). Trasporta type/title/status/
 * detail/errors[] e il correlation_id. Implementa render() così Laravel la serializza direttamente
 * con il content-type corretto, senza un exception handler globale (siamo un package).
 */
final class ApiProblemException extends \RuntimeException
{
    /**
     * @param  array<string, list<string>>  $errors  errori per-campo (validazione)
     */
    public function __construct(
        private readonly int $status,
        private readonly string $title,
        string $detail = '',
        private readonly array $errors = [],
        private readonly string $type = 'about:blank',
    ) {
        parent::__construct($detail !== '' ? $detail : $title);
    }

    public static function unauthorized(string $detail = 'Autenticazione richiesta.'): self
    {
        return new self(401, 'Unauthorized', $detail, type: 'https://iam/problems/unauthorized');
    }

    public static function forbidden(string $detail = 'Permesso negato (fail-closed).'): self
    {
        return new self(403, 'Forbidden', $detail, type: 'https://iam/problems/forbidden');
    }

    public static function notFound(string $detail = 'Risorsa non trovata.'): self
    {
        return new self(404, 'Not Found', $detail, type: 'https://iam/problems/not-found');
    }

    public static function conflict(string $detail): self
    {
        return new self(409, 'Conflict', $detail, type: 'https://iam/problems/conflict');
    }

    /**
     * @param  array<string, list<string>>  $errors
     */
    public static function unprocessable(string $detail, array $errors = []): self
    {
        return new self(422, 'Unprocessable Entity', $detail, $errors, 'https://iam/problems/validation');
    }

    public function render(Request $request): JsonResponse
    {
        $correlationId = $request->headers->get('Correlation-Id');
        $body = [
            'type' => $this->type,
            'title' => $this->title,
            'status' => $this->status,
            'detail' => $this->getMessage(),
            'correlation_id' => is_string($correlationId) ? $correlationId : null,
        ];
        if ($this->errors !== []) {
            $body['errors'] = $this->errors;
        }

        return new JsonResponse($body, $this->status, ['Content-Type' => 'application/problem+json']);
    }
}
