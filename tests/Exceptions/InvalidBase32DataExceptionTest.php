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

use CitrusLab\Totp\Exceptions\InvalidBase32DataException;
use CitrusLab\Totp\Exceptions\TotpException;
use CitrusLab\TotpTests\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(InvalidBase32DataException::class)]
final class InvalidBase32DataExceptionTest extends TestCase
{
    /** Data provider with constructor arguments for the exception for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        yield "data-only" => ["blah",];
        yield "data-and-message" => ["blah", "'blah' is not valid base32 content.",];
        yield "data-message-and-code" => ["blah", "'blah' is not valid base32 content.", 12,];
        yield "data-message-code-and-previous" => ["blah", "'blah' is not valid base32 content.", 12, new TotpException("foo"),];
    }

    /** Ensure the constructor initialises the exception as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(string $data, string $message = "", int $code = 0, Throwable $previous = null): void
    {
        $exception = new InvalidBase32DataException($data, $message, $code, $previous);
        self::assertEquals($data, $exception->getData(), "Invalid Base32 data retrieved from exception was not as expected.");
        self::assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with invalid base32 data for testGetData1(). */
    public static function providerTestGetData1(): iterable
    {
        yield "typical" => ["fizzbuzz",];
        yield "empty" => ["",];
        yield "whitespace" => ["  ",];
    }

    /** Ensure we can retrieve the correct invalid data from the exception. */
    #[DataProvider("providerTestGetData1")]
    public function testGetData1(string $data): void
    {
        $actual = new InvalidBase32DataException($data);
        self::assertEquals($data, $actual->getData(), "Invalid Base32 data retrieved from exception was not as expected.");
    }
}
