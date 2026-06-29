<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Authorization\Pdp;

/**
 * Implicazione fra relazioni (userset rewrite *fisso*, doc 18 §2.4). Una relazione più forte
 * soddisfa il check per una più debole: di default `owner ⊇ editor ⊇ viewer`.
 *
 * Il DSL completo Zanzibar (computed_userset/tupleset arbitrari) è v2; qui una mappa configurabile
 * via `iam.rebac.rewrite` tiene i casi comuni semplici e deterministici.
 */
final class RelationRewrite
{
    /**
     * Mappa relazione → relazioni che la implicano (sé stessa inclusa).
     * `editor` è soddisfatta da {editor, owner}; `viewer` da {viewer, editor, owner}.
     *
     * @var array<string, list<string>>
     */
    private const DEFAULT = [
        'owner' => ['owner'],
        'editor' => ['editor', 'owner'],
        'viewer' => ['viewer', 'editor', 'owner'],
    ];

    /** @var array<string, list<string>> */
    private array $map;

    /** @param array<string, list<string>>|null $map */
    public function __construct(?array $map = null)
    {
        $configured = $map ?? (function (): mixed {
            return function_exists('config') ? config('iam.rebac.rewrite') : null;
        })();

        $this->map = $this->normalize(is_array($configured) ? $configured : self::DEFAULT);
    }

    /**
     * Normalizza una mappa (potenzialmente da config, quindi mixed) nel tipo stretto
     * `array<string, list<string>>`. Voci non valide vengono scartate (fail-closed).
     *
     * @param  array<mixed>  $raw
     * @return array<string, list<string>>
     */
    private function normalize(array $raw): array
    {
        $out = [];
        foreach ($raw as $relation => $implied) {
            if (!is_string($relation) || !is_array($implied)) {
                continue;
            }
            $list = [];
            foreach ($implied as $value) {
                if (is_string($value)) {
                    $list[] = $value;
                }
            }
            $out[$relation] = $list;
        }

        return $out;
    }

    /**
     * Insieme delle relazioni che soddisfano una richiesta di `$relation`.
     * Se la relazione non è nella mappa, soddisfa solo sé stessa (fail-closed: nessuna implicazione implicita).
     *
     * @return list<string>
     */
    public function satisfying(string $relation): array
    {
        $set = $this->map[$relation] ?? [$relation];

        // Garantisce che la relazione stessa sia sempre inclusa (una relazione soddisfa sé stessa).
        return in_array($relation, $set, true) ? $set : [$relation, ...$set];
    }
}
