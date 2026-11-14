<?php
declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__ . '/src')
    ->in(__DIR__ . '/tests')
    ->in(__DIR__ . '/fuzz')
    ->in(__DIR__ . '/scripts');

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(false)
    ->setRules(['@PSR12' => true])
    ->setFinder($finder);
