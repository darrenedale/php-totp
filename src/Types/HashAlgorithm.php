<?php

/*
 * Copyright 2025 Darren Edale
 *
 * This file is part of the php-totp package.
 *
 * php-totp is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License v2.0.
 *
 * php-totp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License v2.0
 * along with php-totp. If not, see <http://www.apache.org/licenses/>.
 */

declare(strict_types=1);

namespace CitrusLab\Totp\Types;

use CitrusLab\Totp\Exceptions\InvalidHashAlgorithmException;
use Stringable;

/** Named type for ensuring valid hashing algorithms. */
final class HashAlgorithm implements Stringable
{
    public const Sha1Algorithm = "sha1";

    public const Sha256Algorithm = "sha256";

    public const Sha512Algorithm = "sha512";

    public const DefaultAlgorithm = self::Sha1Algorithm;

    /** @var string The algorithm to use. */
    private string $algorithm;

    /**
     * Initialise a new HashAlgorithm.
     *
     * @param string $algorithm The algorithm.
     *
     * @throws InvalidHashAlgorithmException if the algorighm is not valid.
     */
    public function __construct(string $algorithm)
    {
        if (self::Sha1Algorithm !== $algorithm && self::Sha256Algorithm !== $algorithm && self::Sha512Algorithm !== $algorithm) {
            throw new InvalidHashAlgorithmException($algorithm, "Expected valid hash algorithm, found \"{$algorithm}\"");
        }

        $this->algorithm = $algorithm;
    }

    /** Get the SHA1 hashing algorithm. */
    public static function sha1(): self
    {
        return new self(self::Sha1Algorithm);
    }

    /** Get the SHA256 hashing algorithm. */
    public static function sha256(): self
    {
        return new self(self::Sha256Algorithm);
    }

    /** Get the SHA512 hashing algorithm. */
    public static function sha512(): self
    {
        return new self(self::Sha512Algorithm);
    }

    /** @return string The algorithm. */
    public function algorithm(): string
    {
        return $this->algorithm;
    }

    public function __toString(): string
    {
        return $this->algorithm;
    }
}
