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

namespace CitrusLab\TotpTests\Exceptions;

use CitrusLab\Totp\Exceptions\InvalidSecretException;
use CitrusLab\Totp\Exceptions\TotpException;
use CitrusLab\TotpTests\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(InvalidSecretException::class)]
final class InvalidSecretExceptionTest extends TestCase
{
    /** Data provider with constructor arguments for the exception for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        yield "secret-only" => ["blah_:",];
        yield "secret-and-message" => ["blah_:", "'blah_:' is not a valid TOTP secret.",];
        yield "secret-message-and-code" => ["blah_:", "'blah_:' is not a valid TOTP secret.", 12,];
        yield "secret-message-code-and-previous" => ["blah_:", "'blah_:' is not a valid TOTP secret.", 12, new TotpException("foo"),];
    }

    /** Ensure the constructor initialises the exception as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor(string $secret, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $actual = new InvalidSecretException($secret, $message, $code, $previous);
        self::assertEquals($secret, $actual->getSecret(), "Invalid secret retrieved from exception was not as expected.");
        self::assertEquals($message, $actual->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $actual->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $actual->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with invalid secrets data for testGetData1(). */
    public static function providerTestGetSecret1(): iterable
    {
        yield "typical" => ["fizzbuzz",];
        yield "empty" => ["",];
        yield "whitespace" => ["  ",];
        yield "invalid" => ["bvcoaw872bkjsd",];
    }

    /** Ensure we can retrieve the correct invalid secret from the exception. */
    #[DataProvider("providerTestGetSecret1")]
    public function testGetSecret1(string $secret): void
    {
        $actual = new InvalidSecretException($secret);
        self::assertEquals($secret, $actual->getSecret(), "Invalid secret retrieved from exception was not as expected.");
    }
}
