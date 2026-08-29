<?php

declare(strict_types=1);

namespace Padosoft\Iam\Domain\Governance\Reviews\Reviewable;

/**
 * Registro delle sorgenti certificabili. Singleton nel container: i moduli opzionali si
 * registrano dal proprio service provider (`app(ReviewableRegistry::class)->register(...)`),
 * come già fanno per il grant OAuth e per le risorse dell'Admin API.
 *
 * Una sorgente sconosciuta NON viene inventata: un item il cui `reviewable_type` non è più
 * registrato (modulo disinstallato) non è revocabile, e l'engine lo lascia `pending` invece di
 * marcarlo `revoked` — certificare una revoca mai avvenuta falsificherebbe l'evidenza d'audit.
 */
final class ReviewableRegistry
{
    /** @var array<string, ReviewableSource> */
    private array $sources = [];

    public function register(ReviewableSource $source): void
    {
        $this->sources[$source->type()] = $source;
    }

    public function for(string $type): ?ReviewableSource
    {
        return $this->sources[$type] ?? null;
    }

    /** @return array<string, ReviewableSource> */
    public function all(): array
    {
        return $this->sources;
    }

    /** @return list<string> */
    public function types(): array
    {
        return array_keys($this->sources);
    }
}
