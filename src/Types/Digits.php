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

use CitrusLab\Totp\Exceptions\InvalidDigitsException;
use Stringable;

final class Digits implements Stringable
{
    /** The minimum number of digits, as per RFC 6238. */
    public const MinimumDigits = 6;

    /** @var int The number of digits. */
    private int $digits;

    /**
     * Initialise a new Digits instance with a digit count.
     *
     * @param int $digits The number of digits.
     *
     * @throws InvalidDigitsException if the number of digits is not valid.
     */
    public function __construct(int $digits)
    {
        if (self::MinimumDigits > $digits) {
            throw new InvalidDigitsException($digits, "Expected digits >= " . self::MinimumDigits . ", found {$digits}");
        }

        $this->digits = $digits;
    }

    /** @return int The number of digits. */
    public function quantity(): int
    {
        return $this->digits;
    }

    /** @return string The stringified number of digits. */
    public function __toString(): string
    {
        return (string) $this->digits;
    }
}
