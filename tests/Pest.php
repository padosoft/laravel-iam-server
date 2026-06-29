<?php

declare(strict_types=1);

use Tests\TestCase;

// I test in tests/Feature/ bootano un'app Laravel via Testbench + il provider IAM server.
// I test in tests/ (root, es. ScaffoldTest) restano unit puri (nessun bootstrap).
uses(TestCase::class)->in('Feature');

// Helper condivisi dai test OAuth (Authorization Code / Refresh Token).
require_once __DIR__.'/Feature/OAuth/OAuthHelpers.php';

// Helper condivisi dai test Applications (manifest validate/diff/apply/lifecycle).
require_once __DIR__.'/Feature/Applications/ApplicationsHelpers.php';
