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
     * @param  array<string, mixed>  $extensions  membri di estensione RFC 9457 (es. required_aal)
     */
    public function __construct(
        private readonly int $status,
        private readonly string $title,
        string $detail = '',
        private readonly array $errors = [],
        private readonly string $type = 'about:blank',
        private readonly array $extensions = [],
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
     * Step-up richiesto (IAM-04): il permesso è concesso ma esige un AAL superiore a quello dell'attore.
     * Non è un permesso negato — l'attore deve ripetere l'autenticazione al livello indicato. Il
     * `required_aal` è esposto come membro di estensione RFC 9457 così il client può avviare lo step-up.
     */
    public static function stepUpRequired(string $requiredAal): self
    {
        return new self(
            403,
            'Step-up required',
            "Questa operazione richiede un livello di autenticazione {$requiredAal}: ripeti l'autenticazione (step-up).",
            type: 'https://iam/problems/step-up-required',
            extensions: ['required_aal' => $requiredAal],
        );
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
        // Membri di estensione RFC 9457 (top-level accanto a type/title/status), senza sovrascrivere i campi standard.
        foreach ($this->extensions as $k => $v) {
            if (!array_key_exists($k, $body)) {
                $body[$k] = $v;
            }
        }

        return new JsonResponse($body, $this->status, ['Content-Type' => 'application/problem+json']);
    }
}
