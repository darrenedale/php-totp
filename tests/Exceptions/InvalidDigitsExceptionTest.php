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

namespace Equit\TotpTests\Exceptions;

use Equit\Totp\Exceptions\InvalidDigitsException;
use Equit\Totp\Exceptions\TotpException;
use Equit\TotpTests\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(InvalidDigitsException::class)]
final class InvalidDigitsExceptionTest extends TestCase
{
    /** Data provider with constructor arguments for the exception for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        for ($digits = 1; $digits < 6; ++$digits) {
            yield "{$digits}-digits" => [$digits];
        }

        yield "digits-and-message" => [1, "1 is not a valid number of digits.",];
        yield "digits-message-and-code" => [1, "1 is not a valid number of digits.", 12,];
        yield "digits-message-code-and-previous" => [1, "1 is not a valid number of digits.", 12, new TotpException("foo"),];
    }

    /** Ensure the constructor initialises the exception as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(int $digits, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $actual = new InvalidDigitsException($digits, $message, $code, $previous);
        self::assertEquals($digits, $actual->getDigits(), "Invalid number of digits retrieved from exception was not as expected.");
        self::assertEquals($message, $actual->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $actual->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $actual->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with invalid digit counts for testGetDigits1(). */
    public static function providerTestGetDigits1(): iterable
    {
        yield "five" => [5,];
        yield "zero" => [0,];
        yield "minus-7" => [-7,];
    }

    /** Ensure we can retrieve the correct invalid digit count from the exception. */
    #[DataProvider('providerTestGetDigits1')]
    public function testGetDigits1(int $digits): void
    {
        $actual = new InvalidDigitsException($digits);
        self::assertEquals($digits, $actual->getDigits(), "Invalid number of digits retrieved from exception was not as expected.");
    }
}
