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

namespace Equit\TotpTests\Types;

use DateInterval;
use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\TotpTests\Framework\TestCase;
use Equit\Totp\Types\TimeStep;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(TimeStep::class)]
final class TimeStepTest extends TestCase
{
    private TimeStep $timeStep;

    public function setUp(): void
    {
        $this->timeStep = new TimeStep(TimeStep::DefaultTimeStep);
    }

    public function tearDown(): void
    {
        unset($this->timeStep);
    }

    /** Data provider with valid time steps for testConstructor1(). */
    public static function providerValidSeconds(): iterable
    {
        for ($seconds = 1; $seconds < 600; ++$seconds) {
            yield "{$seconds}-seconds" => [$seconds];
        }
    }

    /** Ensure we can construct TimeSteps with valid time steps in seconds. */
    #[DataProvider("providerValidSeconds")]
    public function testConstructor1(int $seconds): void
    {
        $timeStep = new TimeStep($seconds);
        self::assertSame($seconds, $timeStep->seconds());
    }

    /** Data provider with invalid time steps for testConstructor2(). */
    public static function providerInvalidSeconds(): iterable
    {
        for ($seconds = 0; $seconds >= -100; --$seconds) {
            yield "{$seconds}-seconds" => [$seconds];
        }

        yield "php-int-min" => [PHP_INT_MIN];
    }

    /** Ensure the constructor throws with invalid time steps. */
    #[DataProvider("providerInvalidSeconds")]
    public function testConstructor2(int $seconds): void
    {
        $this->expectException(InvalidTimeStepException::class);
        $this->expectExceptionMessage("Expected valid TOTP time step, found {$seconds}");
        new TimeStep($seconds);
    }

    /** Ensure we can retrieve the correct number of seconds. */
    public function testSeconds1(): void
    {
        self::assertSame(TimeStep::DefaultTimeStep, $this->timeStep->seconds());
    }

    /** Ensure the fromSeconds() convenience factory creates a TimeStep with the correct number of seconds. */
    #[DataProvider("providerValidSeconds")]
    public function testFromSeconds1(int $seconds): void
    {
        $timeStep = TimeStep::fromSeconds($seconds);
        self::assertSame($seconds, $timeStep->seconds());
    }

    /** Ensure the fromSeconds() convenience factory throws with invalid numbers of seconds. */
    #[DataProvider('providerInvalidSeconds')]
    public function testFromSeconds2(int $seconds): void
    {
        $this->expectException(InvalidTimeStepException::class);
        $this->expectExceptionMessage("Expected valid TOTP time step, found {$seconds}");
        TimeStep::fromSeconds($seconds);
    }

    /** Data provider with valid minutes for testFromMinutes1(). */
    public static function providerTestFromMinutes1(): iterable
    {
        for ($minutes = 1; $minutes <= 60; ++$minutes) {
            yield "{$minutes}-minutes" => [$minutes, 60 * $minutes,];
        }
    }

    /** Ensure the fromMinutes() convenience factory creates a TimeStep with the correct number of seconds. */
    #[DataProvider("providerTestFromMinutes1")]
    public function testFromMinutes1(int $minutes, int $expectedSeconds): void
    {
        $timeStep = TimeStep::fromMinutes($minutes);
        self::assertSame($expectedSeconds, $timeStep->seconds());
    }

    /** Data provider with invalid numbers of minutes for testFromMinutes2(). */
    public static function providerTestFromMinutes2(): iterable
    {
        for ($minutes = 0; $minutes >= -60; --$minutes) {
            yield "{$minutes}-minutes" => [$minutes, 60 * $minutes];
        }
    }

    /** Ensure the fromMinutes() convenience factory throws with invalid numbers of minutes. */
    #[DataProvider("providerTestFromMinutes2")]
    public function testFromMinutes2(int $minutes, $invalidSeconds): void
    {
        $this->expectException(InvalidTimeStepException::class);
        $this->expectExceptionMessage("Expected valid TOTP time step, found {$invalidSeconds}");
        TimeStep::fromMinutes($minutes);
    }

    /** Ensure time steps convert to string as expected. */
    public function testToString1(): void
    {
        self::assertSame("30", $this->timeStep->__toString());
    }

    /** Data provider with valid DateIntervals for testFromDateInterval1(). */
    public static function providerTestFromDateInterval1(): iterable
    {
        yield "one-second" => [new DateInterval("PT1S"), 1,];
        yield "ten-seconds" => [new DateInterval("PT10S"), 10,];
        yield "sixty-seconds" => [new DateInterval("PT60S"), 60,];
        yield "two-minutes-thirty-seconds" => [new DateInterval("PT2M30S"), 150,];
        yield "one-hour" => [new DateInterval("PT1H"), 3600,];
        yield "two-hours-eleven-minutes-three-seconds" => [new DateInterval("PT2H11M3S"), 7863,];
        yield "one-day" => [new DateInterval("P1D"), 86400,];
    }

    /** Ensure we can successfully create a TimeStep from a DateInterval. */
    #[DataProvider("providerTestFromDateInterval1")]
    public function testFromDateInterval1(DateInterval $interval, int $expectedSeconds): void
    {
        $timeStep = TimeStep::fromDateInterval($interval);
        self::assertSame($expectedSeconds, $timeStep->seconds());
    }

    /** Data provider with invalid DateIntervals for testFromDateInterval2(). */
    public static function providerTestFromDateInterval2(): iterable
    {
        yield "has-month" => [new DateInterval("P1MT1S"), 1,];
        yield "has-year" => [new DateInterval("P1YT1S"), 10,];
    }

    /** Ensure the fromDateInterval() convenience factory throws with invalid intervals. */
    #[DataProvider("providerTestFromDateInterval2")]
    public function testFromDateInterval2(DateInterval $interval): void
    {
        $this->expectException(InvalidTimeStepException::class);
        $this->expectExceptionMessage("Expected DateInterval without years or months, found {$interval->y} year(s), {$interval->m} month(s)");
        TimeStep::fromDateInterval($interval);
    }
}
