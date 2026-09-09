<?php

declare(strict_types=1);

namespace Remediate\Engine\Advisory\Db;

final class SourceRecord
{
    public function __construct(
        public readonly string $name,
        public readonly string $remoteId,
        public readonly ?string $url = null,
        public readonly ?\DateTimeImmutable $modifiedAt = null,
    ) {
    }
}
