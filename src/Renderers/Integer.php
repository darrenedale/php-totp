<?php
/*
 * Copyright 2022 Darren Edale
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

namespace Equit\Totp\Renderers;

use Equit\Totp\Exceptions\InvalidDigitsException;

/**
 * Render a TOTP with an arbitrary number of decimal digits.
 *
 * This renders the truncation of the computed HMAC as a number of decimal digits, as specified by the HOTP
 * specification (see RFC 4226, https://datatracker.ietf.org/doc/html/rfc4226). The number of digits must be 6 or more
 * and should ordinarily be 9 or lower.
 */
class Integer implements IntegerRenderer
{
    use RendersStandardIntegerPasswords;

    /**
     * The minimum number of digits, as per RFC 6238.
     */
    public const MinimumDigits = 6;

    /**
     * The default number of digits.
     */
    public const DefaultDigits = 6;

    /**
     * @var int The number of digits.
     */
    protected int $digitCount;

    /**
     * Initialise a new renderer for a given number of digits.
     *
     * @param int $digits The digit count for rendered passwords. Defaults to 6.
     *
     * @throws \Equit\Totp\Exceptions\InvalidDigitsException if the number of digits is < 6.
     */
    public function __construct(int $digits = self::DefaultDigits)
    {
        $this->setDigits($digits);
    }

    /**
     * Set the number of digits in the rendered passwords.
     *
     * The TOTP specification mandates that the rendering contains at least 6 decimal digits. There is little point in
     * specifying more than 9 digits since you're likely to just be adding extra 0 pad characters on the left of the
     * 9-digit rendering.
     *
     * @param int $digits The number of digits.
     *
     * @throws \Equit\Totp\Exceptions\InvalidDigitsException if the number of digits is < 6.
     */
    public function setDigits(int $digits)
    {
        if (self::MinimumDigits > $digits) {
            throw new InvalidDigitsException($digits, "Integer renderers must have at least six digits in the password.");
        }

        $this->digitCount = $digits;
    }
}
