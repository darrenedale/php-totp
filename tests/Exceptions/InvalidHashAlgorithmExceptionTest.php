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

use CitrusLab\Totp\Exceptions\InvalidHashAlgorithmException;
use CitrusLab\Totp\Exceptions\TotpException;
use CitrusLab\TotpTests\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(InvalidHashAlgorithmException::class)]
final class InvalidHashAlgorithmExceptionTest extends TestCase
{
    /** Data provider with constructor arguments for the exception for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        yield "algorithm-only" => ["md5",];
        yield "algorithm-and-message" => ["md5", "'md5' is not a valid TOTP hash algorithm.",];
        yield "algorithm-message-and-code" => ["md5", "'md5' is not a valid TOTP hash algorithm.", 12,];
        yield "algorithm-message-code-and-previous" => ["md5", "'md5' is not a valid TOTP hash algorithm.", 12, new TotpException("foo"),];
    }

    /** Ensure the constructor initialises the exception as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(string $hashAlgorithm, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $actual = new InvalidHashAlgorithmException($hashAlgorithm, $message, $code, $previous);
        self::assertEquals($hashAlgorithm, $actual->getHashAlgorithm(), "Invalid hash algorithm retrieved from exception was not as expected.");
        self::assertEquals($message, $actual->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $actual->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $actual->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with invalid base32 data for testGetAlgorithm1(). */
    public static function providerTestGetAlgorithm1(): iterable
    {
        yield "typical" => ["md5",];
        yield "empty" => ["",];
        yield "nearly-valid" => ["sha1 ",];
        yield "whitespace" => ["  ",];
    }

    /** Ensure we can retrieve the correct invalid hash algorithm from the exception. */
    #[DataProvider("providerTestGetAlgorithm1")]
    public function testGetAlgorithm1(string $secret): void
    {
        $exception = new InvalidHashAlgorithmException($secret);
        self::assertEquals($secret, $exception->getHashAlgorithm(), "Invalid hash algorithm retrieved from exception was not as expected.");
    }
}
