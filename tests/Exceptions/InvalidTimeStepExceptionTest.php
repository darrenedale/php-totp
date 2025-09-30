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

use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\Totp\Exceptions\TotpException;
use Equit\TotpTests\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(InvalidTimeStepException::class)]
final class InvalidTimeStepExceptionTest extends TestCase
{
    /** Data provider with constructor arguments for the exception for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        yield "time-step-only" => [0];
        yield "time-step-message-and-code" => [0, "0 is not a valid time step.", 12,];
        yield "time-step-message-code-and-previous" => [0, "0 is not a valid time step.", 12, new TotpException("foo"),];
        yield "time-step-only-negative" => [-1,];
        yield "time-step-only-int-min" => [PHP_INT_MIN,];
    }

    /** Ensure the constructor initialises the exception as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(int $timeStep, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $actual = new InvalidTimeStepException($timeStep, $message, $code, $previous);
        self::assertEquals($timeStep, $actual->getTimeStep(), "Invalid time step retrieved from exception was not as expected.");
        self::assertEquals($message, $actual->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $actual->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $actual->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with invalid time steps for testGetData1(). */
    public static function providerTestGetTimeStep1(): iterable
    {
        yield "zero" => [0,];
        yield "negative" => [-1,];
        yield "int-min" => [PHP_INT_MIN,];
    }

    /** Ensure we can retrieve the correct invalid time step from the exception. */
    #[DataProvider("providerTestGetTimeStep1")]
    public function testGetTimeStep(int $timeStep): void
    {
        $actual = new InvalidTimeStepException($timeStep);
        self::assertEquals($timeStep, $actual->getTimeStep(), "Invalid time step retrieved from exception was not as expected.");
    }
}
