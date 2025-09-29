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

namespace Equit\TotpTests\Exceptions\UrlGenerator;

use Equit\Totp\Exceptions\TotpException;
use Equit\Totp\Exceptions\UrlGenerator\UnsupportedReferenceTimeException;
use Equit\TotpTests\Framework\TestCase;
use DateTime;
use DateTimeZone;
use Generator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

/** TODO normalise case of test data keys */
#[CoversClass(UnsupportedReferenceTimeException::class)]
final class UnsupportedReferenceTimeExceptionTest extends TestCase
{
    /** Unix timestamp of a very early time (80 years before the epoch started). */
    private const MinTimestamp = -80 * 365 * 24 * 60 * 60;

    /** Unix timestamp of a very late time (80 years after the epoch started). */
    private const MaxTimestamp = 80 * 365 * 24 * 60 * 60;

    /**
     * Data provider with arguments for the exception constructor for testConstructor1().
     *
     * @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument.
     */
    public static function providerTestConstructor1(): iterable
    {
        yield "typicalTimestamp60" => [60,];
        yield "typicalTimestamp120" => [120,];
        yield "typicalTimestampNow" => [time(),];
        yield "typicalDateTime60" => [new DateTime("@60", new DateTimeZone("UTC")),];
        yield "typicalDateTime120" => [new DateTime("@120", new DateTimeZone("UTC")),];
        yield "typicalDateTimeNow" => [new DateTime("@" . time(), new DateTimeZone("UTC")),];
        yield "typicalTimestampAndMessage" => [60, "60 is not a valid reference time.",];
        yield "typicalTimestampMessageAndCode" => [60, "60 is not a valid reference time.", 12,];
        yield "typicalTimestampMessageCodeAndPrevious" => [60, "60 is not a valid reference time.", 12, new TotpException("foo"),];
        yield "typicalDateTimeAndMessage" => [new DateTime("@60", new DateTimeZone("UTC")), "60 is not a valid reference time.",];
        yield "typicalDateTimeMessageAndCode" => [new DateTime("@60", new DateTimeZone("UTC")), "60 is not a valid reference time.", 12,];
        yield "typicalDateTimeMessageCodeAndPrevious" => [new DateTime("@60", new DateTimeZone("UTC")), "60 is not a valid reference time.", 12, new TotpException("foo"),];
        yield "extremeVeryEarly" => [self::MinTimestamp,];
        yield "extremeVeryLate" => [self::MaxTimestamp,];
    }

    /** Ensure the constructor processes all arguments as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(int|DateTime $time, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $exception = new UnsupportedReferenceTimeException($time, $message, $code, $previous);

        if ($time instanceof DateTime) {
            $timestamp = $time->getTimestamp();
        } else {
            $timestamp = $time;
            /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
            $time = new DateTime("@{$time}", new DateTimeZone("UTC"));
        }

        self::assertEquals($time, $exception->getTime(), "Unsupported DateTime retrieved from exception was not as expected.");
        self::assertEquals($timestamp, $exception->getTimestamp(), "Timestamp retrieved from exception was not as expected.");
        self::assertEquals($message, $exception->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $exception->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $exception->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /**
     * Data provider with reference times or timestamps and expected timestamps for testGetTimestamp1().
     *
     * @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument.
     */
    public static function providerTestGetTimestamp1(): iterable
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
        yield "typicalTimestamp60" => [60, 60,];
        yield "extremeVeryEarly" => [self::MinTimestamp, self::MinTimestamp,];
        yield "extremeVeryLate" => [self::MaxTimestamp, self::MaxTimestamp,];
        yield "typicalDateTime60" => [new DateTime("@60", new DateTimeZone("UTC")), 60,];
        yield "extremeDateTimeVeryEarly" => [new DateTime("@" . self::MinTimestamp, new DateTimeZone("UTC")), self::MinTimestamp,];
        yield "extremeDateTimeVeryLate" => [new DateTime("@" . self::MaxTimestamp, new DateTimeZone("UTC")), self::MaxTimestamp,];

        $nowTimestamp = time();
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
        $nowTime = new DateTime("@{$nowTimestamp}", new DateTimeZone("UTC"));
        yield "typicalNow" => [$nowTimestamp, $nowTimestamp,];
        yield "typicalDateTimeNow" => [$nowTime, $nowTimestamp,];
    }

    /** Ensure we get the correct reference timestamp from the exception. */
    #[DataProvider("providerTestGetTimestamp1")]
    public function testGetTimestamp1(int|DateTime $time, int $expectedTimestamp): void
    {
        $exception = new UnsupportedReferenceTimeException($time);
        self::assertEquals($expectedTimestamp, $exception->getTimestamp(), "Unsupported reference timestamp retrieved from exception was not as expected.");
    }

    /**
     * Data provider with reference times or timestamps and expected times for testGetTime1().
     *
     * @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with timestamp argument.
     */
    public static function providerTestGetTime1(): Generator
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
        yield "typicalTimestamp60" => [60, new DateTime("@60", new DateTimeZone("UTC")),];
        yield "extremeVeryEarly" => [self::MinTimestamp, new DateTime("@" . self::MinTimestamp, new DateTimeZone("UTC")),];
        yield "extremeVeryLate" => [self::MaxTimestamp, new DateTime("@" . self::MaxTimestamp, new DateTimeZone("UTC")),];
        yield "typicalDateTime60" => [new DateTime("@60", new DateTimeZone("UTC")), new DateTime("@60", new DateTimeZone("UTC")),];
        yield "extremeDateTimeVeryEarly" => [new DateTime("@" . self::MinTimestamp, new DateTimeZone("UTC")), new DateTime("@" . self::MinTimestamp, new DateTimeZone("UTC")),];
        yield "extremeDateTimeVeryLate" => [new DateTime("@" . self::MaxTimestamp, new DateTimeZone("UTC")), new DateTime("@" . self::MaxTimestamp, new DateTimeZone("UTC")),];

        $nowTimestamp = time();
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with a timestamp argument. */
        $nowTime = new DateTime("@{$nowTimestamp}", new DateTimeZone("UTC"));
        yield "typicalNow" => [$nowTimestamp, $nowTime,];
        yield "typicalDateTimeNow" => [$nowTime, $nowTime,];
    }

    /** Ensure we get the correct reference time from the exception. */
    #[DataProvider("providerTestGetTime1")]
    public function testGetTime1(int|DateTime $time, DateTime $expectedTime): void
    {
        $exception = new UnsupportedReferenceTimeException($time);
        self::assertEquals($expectedTime, $exception->getTime(), "Unsupported DateTime retrieved from exception was not as expected.");
    }
}
