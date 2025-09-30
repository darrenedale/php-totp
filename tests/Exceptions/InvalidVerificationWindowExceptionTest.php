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

use Equit\Totp\Exceptions\InvalidVerificationWindowException;
use Equit\Totp\Exceptions\TotpException;
use Equit\TotpTests\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(InvalidVerificationWindowException::class)]
final class InvalidVerificationWindowExceptionTest extends TestCase
{
    /** Data provider with constructor arguments for the exception for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        yield "window-only" => [-1];
        yield "window-message-and-code" => [-1, "-1 is not a valid verification window.", 12,];
        yield "window-message-code-and-previous" => [-1, "-1 is not a valid verification window.", 12, new TotpException("foo"),];
        yield "window-only-int-min" => [PHP_INT_MIN,];
    }

    /** Ensure the constructor initialises the exception as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(int $window, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $actual = new InvalidVerificationWindowException($window, $message, $code, $previous);
        self::assertEquals($window, $actual->getWindow(), "Invalid window retrieved from exception was not as expected.");
        self::assertEquals($message, $actual->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $actual->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $actual->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with invalid windows for testGetWindow1(). */
    public static function providerTestGetWindow1(): iterable
    {
        yield "negative" => [-1,];
        yield "int-min" => [PHP_INT_MIN,];
    }

    /** Ensure we can retrieve the correct invalid window from the exception. */
    #[DataProvider("providerTestGetWindow1")]
    public function testGetWindow1(int $window): void
    {
        $actual = new InvalidVerificationWindowException($window);
        self::assertEquals($window, $actual->getWindow(), "Invalid window retrieved from exception was not as expected.");
    }
}
