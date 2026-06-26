<?php

declare(strict_types=1);

namespace Padosoft\Iam\Http\Controllers\OAuth;

use GuzzleHttp\Psr7\HttpFactory;
use Illuminate\Http\Request;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;

/**
 * Bridge HTTP Laravel <-> PSR-7 per gli endpoint OAuth (league lavora in PSR-7).
 * guzzle/psr7 fornisce le factory PSR-17; symfony/psr-http-message-bridge la conversione.
 */
trait BridgesPsr7
{
    private function toPsrRequest(Request $request): ServerRequestInterface
    {
        $psr17 = new HttpFactory;

        return (new PsrHttpFactory($psr17, $psr17, $psr17, $psr17))->createRequest($request);
    }

    private function emptyPsrResponse(): ResponseInterface
    {
        return (new HttpFactory)->createResponse();
    }

    private function toSymfonyResponse(ResponseInterface $psrResponse): Response
    {
        return (new HttpFoundationFactory)->createResponse($psrResponse);
    }
}
