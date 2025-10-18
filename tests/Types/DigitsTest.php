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

namespace CitrusLab\TotpTests\Types;

use CitrusLab\Totp\Exceptions\InvalidDigitsException;
use CitrusLab\TotpTests\Framework\TestCase;
use CitrusLab\Totp\Types\Digits;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(Digits::class)]
final class DigitsTest extends TestCase
{
    private Digits $digits;

    public function setUp(): void
    {
        /** @noinspection PhpUnhandledExceptionInspection Constructor won't throw with 8. */
        $this->digits = new Digits(8);
    }

    public function tearDown(): void
    {
        unset($this->digits);
    }

    /** Data provider with valid quantities of digits for the constructor. */
    public static function providerTestConstructor1(): iterable
    {
        for ($digits = 6; $digits < 15; ++$digits) {
            yield "{$digits}-digits" => [$digits];
        }
    }

    /** Ensure constructor accepts valid digit counts. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(int $digits): void
    {
        /** @noinspection PhpUnhandledExceptionInspection Constructor shouldn't throw with test data. */
        $instance = new Digits($digits);
        self::assertSame($digits, $instance->quantity());
    }

    /** Data provider with invalid quantities of digits for the constructor. */
    public static function providerTestConstructor2(): iterable
    {
        for ($digits = -1; $digits < 6; ++$digits) {
            yield "{$digits}-digits" => [$digits];
        }

        yield "min-int-digits" => [PHP_INT_MIN];
    }

    /** Ensure constructor throws with invalid digit counts. */
    #[DataProvider("providerTestConstructor2")]
    public function testConstructor2(int $digits): void
    {
        self::expectException(InvalidDigitsException::class);
        self::expectExceptionMessage("Expected digits >= 6, found {$digits}");
        new Digits($digits);
    }

    /** Ensure we can read the number of digits. */
    public function testDigits1(): void
    {
        self::assertSame(8, $this->digits->quantity());
    }

    /** Ensure the number of digits is stringified as expected. */
    public function testToString1(): void
    {
        self::assertSame("8", $this->digits->__toString());
    }
}
