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

namespace CitrusLab\TotpTests\Exceptions\UrlGenerator;

use CitrusLab\Totp\Exceptions\TotpException;
use CitrusLab\Totp\Exceptions\UrlGenerator\InvalidUserException;
use CitrusLab\TotpTests\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(InvalidUserException::class)]
final class InvalidUserExceptionTest extends TestCase
{
    /** Data provider with arguments for the exception constructor for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        yield "user-only" => ["darren",];
        yield "user-and-message" => ["clifford", "'clifford' is not a valid user.",];
        yield "user-message-and-code" => ["artemis", "'artemis' is not a valid user.", 12,];
        yield "user-message-code-and-previous" => ["roxy", "'roxy' is not a valid user.", 12, new TotpException("foo"),];
    }

    /** Ensure the constructor processes all arguments as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(string $user, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $exception = new InvalidUserException($user, $message, $code, $previous);
        self::assertEquals($user, $exception->getUser(), "Invalid user retrieved from exception was not as expected.");
        self::assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with user names for testGetUser1(). */
    public static function providerTestGetUser1(): iterable
    {
        yield "empty" => ["",];
        yield "whitespace" => ["  ",];
        yield "filled" => ["darren",];
    }

    /** Ensure we can retrieve the correct user from the exception. */
    #[DataProvider("providerTestGetUser1")]
    public function testGetUser1(string $user): void
    {
        $exception = new InvalidUserException($user);
        self::assertEquals($user, $exception->getUser(), "Invalid user retrieved from exception was not as expected.");
    }
}
