<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Symfony\Component\Yaml\Yaml;

/** @return array<string, mixed> */
function openApiSpec(): array
{
    $path = dirname(__DIR__, 3).'/resources/openapi.yaml';
    $spec = Yaml::parseFile($path);

    return is_array($spec) ? $spec : [];
}

it('la spec OpenAPI è ben formata (3.x, bearer, paths)', function () {
    $spec = openApiSpec();

    expect($spec['openapi'] ?? '')->toStartWith('3.')
        ->and($spec['components']['securitySchemes']['bearerAuth']['scheme'] ?? null)->toBe('bearer')
        ->and($spec['paths'] ?? [])->not->toBeEmpty();
});

it('OGNI rotta Admin API registrata è documentata nella spec (path + metodo)', function () {
    $spec = openApiSpec();
    $paths = is_array($spec['paths'] ?? null) ? $spec['paths'] : [];

    /** @var Router $router */
    $router = app('router');
    $missing = [];

    foreach ($router->getRoutes() as $route) {
        $uri = $route->uri();
        if (!str_starts_with($uri, 'api/iam/v1/')) {
            continue;
        }
        $specPath = substr($uri, strlen('api/iam/v1'));   // già con lo slash iniziale: '/users/{user}'
        $specPath = rtrim($specPath, '/') ?: $specPath;

        foreach ($route->methods() as $method) {
            $method = strtolower($method);
            if (!in_array($method, ['get', 'post', 'put', 'patch', 'delete'], true)) {
                continue; // ignora HEAD/OPTIONS generati da Laravel
            }
            if (!isset($paths[$specPath][$method])) {
                $missing[] = strtoupper($method).' '.$specPath;
            }
        }
    }

    expect($missing)->toBe([]);
});
