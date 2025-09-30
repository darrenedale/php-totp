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

use Equit\Totp\Exceptions\InvalidTimeException;
use Equit\Totp\Exceptions\TotpException;
use Equit\TotpTests\Framework\TestCase;
use DateTime;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(InvalidTimeException::class)]
final class InvalidTimeExceptionTest extends TestCase
{
    /** Data provider with constructor arguments for the exception for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        yield "timestamp-only-zero" => [0,];
        yield "timestamp-only-minute" => [60,];
        yield "timestamp-only-now" => [time(),];
        yield "datetime-only-epoch" => [new DateTime("@0", new DateTimeZone("UTC")),];
        yield "datetime-only-minute" => [new DateTime("@60", new DateTimeZone("UTC")),];
        yield "datetime-only-now" => [new DateTime("@" . time(), new DateTimeZone("UTC")),];
        yield "timestamp-and-message" => [0, "0 is not a valid time.",];
        yield "timestamp-message-and-code" => [0, "0 is not a valid time.", 12,];
        yield "timestamp-message-code-and-previous" => [0, "0 is not a valid time.", 12, new TotpException("foo"),];
        yield "time-and-message" => [new DateTime("@0", new DateTimeZone("UTC")), "Unix epoch is not a valid time.",];
        yield "time-message-and-code" => [new DateTime("@0", new DateTimeZone("UTC")), "Unix epoch is not a valid time.", 12,];
        yield "time-message-code-and-previous" => [new DateTime("@0", new DateTimeZone("UTC")), "Unix epoch is not a valid time.", 12, new TotpException("foo"),];
        yield "timestamp-int-min" => [PHP_INT_MIN,];
        yield "time-max" => [new DateTime("9999-12-31 23:59:59", new DateTimeZone("UTC")),];
    }

    /** Ensure the constructor initialises the exception as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor(DateTime|int $time, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $actual = new InvalidTimeException($time, $message, $code, $previous);

        if ($time instanceof DateTime) {
            $timestamp = $time->getTimestamp();
        } else {
            $timestamp = $time;
            /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument. */
            $time = new DateTime("@{$time}", new DateTimeZone("UTC"));
        }

        self::assertEquals($time, $actual->getTime(), "DateTime retrieved from exception was not as expected.");
        self::assertEquals($timestamp, $actual->getTimestamp(), "Timestamp retrieved from exception was not as expected.");
        self::assertEquals($message, $actual->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $actual->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $actual->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with invalid timestamps for testGetTimestamp1(). */
    public static function providerTestGetTimestamp1(): iterable
    {
        yield "zero" => [0,];
        yield "int-min" => [PHP_INT_MIN,];
        yield "now" => [time(),];
    }

    /** Ensure we can retrieve the correct invalid timestamp from the exception. */
    #[DataProvider("providerTestGetTimestamp1")]
    public function testGetTimestamp1(int $timestamp): void
    {
        $actual = new InvalidTimeException($timestamp);
        self::assertEquals($timestamp, $actual->getTimestamp(), "Invalid timestamp retrieved from exception was not as expected.");
    }

    /** Data provider with invalid timestamps and DateTime objects for testGetDateTime1(). */
    public static function providerTestGetDateTime1(): iterable
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument. */
        yield "zero" => [0, new DateTime("@0", new DateTimeZone("UTC")),];
        yield "int-min" => [PHP_INT_MIN, new DateTime("@" . PHP_INT_MIN, new DateTimeZone("UTC")),];

        $now = time();
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument. */
        yield "now" => [$now, new DateTime("@{$now}", new DateTimeZone("UTC")),];
    }

    /** Ensure we can retrieve the correct invalid DateTime from the exception. */
    #[DataProvider("providerTestGetDateTime1")]
    public function testGetDateTime1(int $timestamp, DateTime $expectedTime): void
    {
        $exception = new InvalidTimeException($timestamp);
        self::assertEquals($expectedTime, $exception->getTime(), "Invalid DateTime retrieved from exception was not as expected.");
    }
}
