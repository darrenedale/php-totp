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

namespace CitrusLab\TotpTests;

use CitrusLab\Totp\Contracts\Renderer;
use CitrusLab\Totp\Exceptions\InvalidTimeException;
use CitrusLab\Totp\Exceptions\InvalidVerificationWindowException;
use CitrusLab\Totp\Renderers\EightDigits;
use CitrusLab\Totp\Renderers\Integer;
use CitrusLab\Totp\Renderers\SixDigits;
use CitrusLab\Totp\Totp;
use CitrusLab\Totp\Types\Digits;
use CitrusLab\Totp\Types\HashAlgorithm;
use CitrusLab\TotpTests\Framework\TestCase;
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;
use CitrusLab\Totp\Types\TimeStep;
use DateTime;
use DateTimeZone;
use Equit\XRay\XRay;
use Mokkd;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(Totp::class)]
final class TotpTest extends TestCase
{
    /** Just a random secret to use to initialise a Totp instance for testing. */
    protected const TestSecret = "hNDl963Ns6a1gp9d5aZ6";

    /** Create a default Totp instance, optionally customised according to the arguments. */
    private static function createTotp(string $secret = self::TestSecret, ?Renderer $renderer = null, int|DateTime $referenceTime = 0, int $timeStep = 30, string $hashAlgorithm = HashAlgorithm::DefaultAlgorithm): Totp
    {
        return new Totp(
            Secret::fromRaw($secret),
            $renderer ?? new SixDigits(),
            new TimeStep($timeStep),
            $referenceTime,
            new HashAlgorithm($hashAlgorithm),
        );
    }

    /**
     * Helper to get a user-readable string representation of a binary string.
     *
     * The binary is converted to a sequence of hex values between 0x00 and 0xff inclusive.
     *
     * @param string $binaryString The binary string to convert.
     *
     * @return string The user-readable string.
     */
    protected static function hexOf(string $binaryString): string
    {
        return "0x" . implode(" 0x", str_split(bin2hex($binaryString), 2));
    }

    /**
     * Helper to get a number of years as an approximate number of seconds.
     *
     * Used when generating test data for the baseline date methods. Doesn't account for leap years or leap seconds.
     *
     * @param int $years The number of years.
     *
     * @return int The number of seconds.
     */
    protected static function yearsInSeconds(int $years): int
    {
        return $years * 365 * 24 * 60 * 60;
    }

    /**
     * Helper to get a number of days as a number of seconds.
     *
     * Used when generating test data for the baseline date methods.
     *
     * @param int $days The number of days.
     *
     * @return int The number of seconds.
     */
    protected static function daysInSeconds(int $days): int
    {
        return $days * 24 * 60 * 60;
    }

    protected function tearDown(): void
    {
        Mokkd::close();
        parent::tearDown();
    }

    /** Data provider with secrets for testDestructor1(). */
    public static function providerTestDestructor1(): iterable
    {
        yield "ascii-secret" => ["password-password"];
        yield "16-null-byte-secret" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"];
        yield "20-null-byte-secret" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"];
    }

    /** Ensure the destructor securely scrubs its internal secret string. */
    #[DataProvider("providerTestDestructor1")]
    public function testDestructor1(string $secret): void
    {
        /** @noinspection PhpUnhandledExceptionInspection Secret::fromRaw() shouldn't throw with the test data. */
        $totp = (new Factory())->totp(Secret::fromRaw($secret));

        $totp->__destruct();
        self::assertAllCharactersHaveChanged($secret, (new XRay($totp))->secret, "The secret was not overwritten with random data.");
    }

    /** Data provider with secrets and their base32 encoded equivalents for testBase32Secret1(). */
    public static function providerTestBase32Secret1(): iterable
    {
        yield "plain-text" => ["password-password", "OBQXG43XN5ZGILLQMFZXG53POJSA====",];
        yield "binary" => ["\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d", "CVYNPLS6RDRTYW2JY6U46JPTD7N2Z645",];
        yield "binary-zeroes" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",];
        yield "binary-ones" => ["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "77777777777777777777777777777777",];
        yield "long-binary" => [
            "\x4d\x51\xa7\x96\x6f\x8f\xf6\xcb\x19\xb5\x61\x2f\xe8\x77\xa8\x78\x26\xb7\xcc\x92\x09\xa0\xe0\x6c\x1a\x8e\x99\x30\x61\x1c\xfc\x18\xd4\x9e\xae\x78\x0c\xc0\x5e\x73\x0c\xd5\x55\x25\x5b\x39\x2a\xd9\x64\x95\xf5\x36\xa5\xe8\x64\x06\xf0\x73\x58\xfc\xfa\x27\xd5\x15\xe5\xa9\x62\xce\x0c\x04\x1e\xa6\xbd\xbc\xde\x61\xb5\x95\xca\x42\x94\xb5\x1b\x1e\xe3\x8c\xde\x14\xb2\x8a\x00\x10\xd4\x96\xa8\xd0\x33\xf6\x7e\x85\xc4\x3e\x94\x5c\xe2\xe5\x6a\x24\x5a\x5e\x27\x2c\xd0\xed\xb0\x33\xe4\x4e\x1a\xcc",
            "JVI2PFTPR73MWGNVMEX6Q55IPATLPTESBGQOA3A2R2MTAYI47QMNJHVOPAGMAXTTBTKVKJK3HEVNSZEV6U3KL2DEA3YHGWH47IT5KFPFVFRM4DAED2TL3PG6MG2ZLSSCSS2RWHXDRTPBJMUKAAINJFVI2AZ7M7UFYQ7JIXHC4VVCIWS6E4WNB3NQGPSE4GWM",
        ];
    }

    /** Ensure we can fetch the base32 of the secret. */
    #[DataProvider("providerTestBase32Secret1")]
    public function testBase32Secret1(string|null $raw, mixed $expectedBase32): void
    {
        $totp = self::createTotp($raw);
        self::assertSame($expectedBase32, $totp->base32Secret(), "The base32 of the raw secret '" . self::hexOf($raw) . "' did not match the expected string.");
    }

    /** Data provider with secrets and their base64 encoded equivalents for testBase64Secret1(). */
    public static function providerTestBase64Secret(): iterable
    {
        yield "plain-text" => ["password-password", "cGFzc3dvcmQtcGFzc3dvcmQ=",];
        yield "binary" => ["\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d", "FXDXrl6I4zxbScepzyXzH9us+50=",];
        yield "binary-zeroes" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",];
        yield "binary-ones" => ["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "//////////////////////////8=",];
        yield "long-binary" => [
            "\x4d\x51\xa7\x96\x6f\x8f\xf6\xcb\x19\xb5\x61\x2f\xe8\x77\xa8\x78\x26\xb7\xcc\x92\x09\xa0\xe0\x6c\x1a\x8e\x99\x30\x61\x1c\xfc\x18\xd4\x9e\xae\x78\x0c\xc0\x5e\x73\x0c\xd5\x55\x25\x5b\x39\x2a\xd9\x64\x95\xf5\x36\xa5\xe8\x64\x06\xf0\x73\x58\xfc\xfa\x27\xd5\x15\xe5\xa9\x62\xce\x0c\x04\x1e\xa6\xbd\xbc\xde\x61\xb5\x95\xca\x42\x94\xb5\x1b\x1e\xe3\x8c\xde\x14\xb2\x8a\x00\x10\xd4\x96\xa8\xd0\x33\xf6\x7e\x85\xc4\x3e\x94\x5c\xe2\xe5\x6a\x24\x5a\x5e\x27\x2c\xd0\xed\xb0\x33\xe4\x4e\x1a\xcc",
            "TVGnlm+P9ssZtWEv6HeoeCa3zJIJoOBsGo6ZMGEc/BjUnq54DMBecwzVVSVbOSrZZJX1NqXoZAbwc1j8+ifVFeWpYs4MBB6mvbzeYbWVykKUtRse44zeFLKKABDUlqjQM/Z+hcQ+lFzi5WokWl4nLNDtsDPkThrM",
        ];
    }

    /** Ensure we can fetch the base64 of the secret. */
    #[DataProvider("providerTestBase64Secret")]
    public function testBase64Secret1(string $raw, string $base64): void
    {
        $totp = self::createTotp($raw);
        self::assertSame($base64, $totp->base64Secret(), "The base64 of the raw secret '" . self::hexOf($raw) . "' did not match the expected string.");
    }

    /** Data provider with valid hash algorithms for testHashAlgorithm1(). */
    public static function providerTestHashAlgorithm1(): iterable
    {
        yield "sha-1" => [HashAlgorithm::Sha1Algorithm,];
        yield "sha-256" => [HashAlgorithm::Sha256Algorithm,];
        yield "sha-512" => [HashAlgorithm::Sha512Algorithm,];
    }

    /** Ensure we can fetch the hash algorithm. */
    #[DataProvider("providerTestHashAlgorithm1")]
    public function testHashAlgorithm(string $algorithm): void
    {
        $totp = self::createTotp(hashAlgorithm: $algorithm);
        self::assertSame($algorithm, $totp->hashAlgorithm()->algorithm(), "The hash algorithm was expected to be {$algorithm} but {$totp->hashAlgorithm()->algorithm()} was reported.");
    }

    /** Date provider with valid reference times for dataForTestReferenceTimestamp(). */
    public static function providerTestReferenceTime1(): iterable
    {
        yield "epoch" => [0,];
        yield "epochAsDateTime" => [new DateTime("@0"), 0,];
        yield "epochAsDateTimeUtc+4" => [new DateTime("@0", new DateTimeZone("UTC")), 0,];
        yield "nowAsTimestamp" => [time(),];
        yield "10YearsAgoAsTimestamp" => [time() - self::yearsInSeconds(10),];
        yield "10DaysAgoAsTimestamp" => [time() - self::daysInSeconds(10),];
        yield "10YearsAfterEpoch" => [self::yearsInSeconds(10),];
        yield "20YearsAfterEpoch" => [self::yearsInSeconds(20),];
        yield "30YearsAfterEpoch" => [self::yearsInSeconds(30),];
        yield "10SecondsAfterEpoch" => [self::daysInSeconds(10),];
        yield "20SecondsAfterEpoch" => [self::daysInSeconds(20),];
        yield "30SecondsAfterEpoch" => [self::daysInSeconds(30),];
        yield "40SecondsAfterEpoch" => [self::daysInSeconds(40),];
        yield "50SecondsAfterEpoch" => [self::daysInSeconds(50),];
        yield "60SecondsAfterEpoch" => [self::daysInSeconds(60),];
        yield "70SecondsAfterEpoch" => [self::daysInSeconds(70),];
        yield "80SecondsAfterEpoch" => [self::daysInSeconds(80),];
        yield "90SecondsAfterEpoch" => [self::daysInSeconds(90),];
        yield "100SecondsAfterEpoch" => [self::daysInSeconds(100),];
        yield "nowAsDateTime" => [new DateTime("@" . time()), time(),];
        yield "dateTimeUtc" => [new DateTime("23-04-1974", new DateTimeZone("UTC")), 135907200,];
        yield "dateTimeUtc-4" => [new DateTime("28-01-1978", new DateTimeZone("-0400")), 254808000,];
        yield "dateTimeUtc+4" => [new DateTime("19-07-2000", new DateTimeZone("+0400")), 963950400,];
        yield "dateTimeUtc-6" => [new DateTime("04-03-1984", new DateTimeZone("-0600")), 447228000,];
        yield "dateTimeUtc+6" => [new DateTime("31-12-1999", new DateTimeZone("+0600")), 946576800,];
    }

    /** Ensure we fetch the expected reference time and timestamp. */
    #[DataProvider("providerTestReferenceTime1")]
    public function testReferenceTime1(int|DateTime $time, ?int $expectedTimestamp = null): void
    {
        $totp     = self::createTotp(referenceTime: $time);

        if (null === $expectedTimestamp) {
            $expectedTimestamp = $time;
            $time = new DateTime("@{$time}", new DateTimeZone("UTC"));
        }

        self::assertEquals($time, $totp->referenceTime());
        self::assertSame($expectedTimestamp, $totp->referenceTimestamp());
    }

    /**
     * Data provider with a number of valid time steps for testTimeStep1(). */
    public static function providerTestTimeStep1(): iterable
    {
        // test with all valid time steps up to 1 hour
        for ($timeStep = 1; $timeStep <= 3600; ++$timeStep) {
            yield [$timeStep,];
        }
    }

    /** Ensure we fetch the expected time-step from timeStep(). */
    #[DataProvider("providerTestTimeStep1")]
    public function testTimeStep1(int $timeStep): void
    {
        $totp = self::createTotp(timeStep: $timeStep);
        self::assertSame($timeStep, $totp->timeStep()->seconds(), "The time step {$timeStep} was expected but {$totp->timeStep()} was reported");
    }

    /**
     * Test data for testSecret.
     *
     * @return iterable
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function providerTestSecret1(): iterable
    {
        yield "plain-text" => ["password-password",];
        yield "binary" => ["\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d",];
        yield "binary-zeroes" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",];
        yield "binary-ones" => ["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",];
        yield "long-binary" => [
            "\x4d\x51\xa7\x96\x6f\x8f\xf6\xcb\x19\xb5\x61\x2f\xe8\x77\xa8\x78\x26\xb7\xcc\x92\x09\xa0\xe0\x6c\x1a\x8e\x99\x30\x61\x1c\xfc\x18\xd4\x9e\xae\x78\x0c\xc0\x5e\x73\x0c\xd5\x55\x25\x5b\x39\x2a\xd9\x64\x95\xf5\x36\xa5\xe8\x64\x06\xf0\x73\x58\xfc\xfa\x27\xd5\x15\xe5\xa9\x62\xce\x0c\x04\x1e\xa6\xbd\xbc\xde\x61\xb5\x95\xca\x42\x94\xb5\x1b\x1e\xe3\x8c\xde\x14\xb2\x8a\x00\x10\xd4\x96\xa8\xd0\x33\xf6\x7e\x85\xc4\x3e\x94\x5c\xe2\xe5\x6a\x24\x5a\x5e\x27\x2c\xd0\xed\xb0\x33\xe4\x4e\x1a\xcc",
        ];
    }

    /** Ensure we get the expected secret from secret(). */
    #[DataProvider("providerTestSecret1")]

    public function testSecret(string $secret): void
    {
        $totp = self::createTotp($secret);
        self::assertSame($secret, $totp->secret(), "The secret returned from Totp::secret() is not as expected.");
    }

    /** Data provider with Renderer instances for testRenderer1(). */
    public static function providerTestRenderer1(): iterable
    {
        /** @noinspection PhpUnhandledExceptionInspection Integer renderer constructor shouldn't throw with test data. */
        yield "sixDigits" => [new SixDigits(),];
        yield "eightDigits" => [new EightDigits(),];
        yield "integer6Digits" => [new Integer(new Digits(6)),];
        yield "integer7Digits" => [new Integer(new Digits(7)),];
        yield "integer8Digits" => [new Integer(new Digits(8)),];
        yield "integer9Digits" => [new Integer(new Digits(9)),];
        yield "integer10Digits" => [new Integer(new Digits(10)),];
        yield "anonymousClass" => [new class implements Renderer
            {
                public function name(): string
                {
                    return "insecure renderer";
                }

                public function render(string $hmac): string
                {
                    return "insecure";
                }
        },];
    }

    /** Ensure we fetch the expected Renderer from renderer(). */
    #[DataProvider("providerTestRenderer1")]
    public function testRenderer1(Renderer $renderer): void
    {
        $totp = self::createTotp(renderer: $renderer);
        self::assertEquals($renderer, $totp->renderer(), "Unexpected object returned from renderer() method.");
    }

    /** Data provider with a timestamp, the expected counter at that timestamp, and optional reference timestamp and
     * time-step for testCounterAt1(). */
    public static function providerTestCounterAt1(): iterable
    {
        // test data from RFC 6238
        yield [59, 1,];
        yield [1111111109, 37037036,];
        yield [1111111111, 37037037,];
        yield [1234567890, 41152263,];
        yield [2000000000, 66666666,];
        yield [20000000000, 666666666,];

        // test data for non-default reference time
        yield [119, 1, 60,];
        yield [121, 2, 60,];

        // test data for non-default time step
        yield [59, 5, null, 10,];
        yield [61, 6, null, 10,];

        // test data for non-default time step and non-default reference time
        yield [119, 5, 60, 10,];
        yield [121, 6, 60, 10,];
    }

    /**
     * @param int|\DateTime $currentTime The time at which to test the counter.
     * @param int $expectedCounter The expected value for the counter.
     * @param int|\DateTime|null $referenceTime The reference time for the test TOTP. Default is null: the default for
     * the Totp will be used (the Unix epoch).
     * @param int|null $timeStep The time step for the test TOTP. Default is null: the default for the Totp will be used
     * (30 seconds).
     * @param class-string|null $exceptionClass The class of exception expected to be thrown, if any.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::setTimeStep() should not throw with test data.
     * Totp::counterAt() should only throw expected test exceptions.
     */
    #[DataProvider("providerTestCounterAt1")]
    public function testCounterAt1(int|DateTime $currentTime, int $expectedCounter, int|DateTime|null $referenceTime = null, ?int $timeStep = null, ?string $exceptionClass = null): void
    {
        $totp = self::createTotp(referenceTime: $referenceTime ?? 0, timeStep: $timeStep ?? 30);

        /** @noinspection PhpUnhandledExceptionInspection counterAt() should only throw expected test exceptions. */
        $actualCounter = $totp->counterAt($currentTime);
        self::assertSame($expectedCounter, $actualCounter, "The counter is expected to be {$expectedCounter} but is actually {$actualCounter}.");
    }

    /** Ensure we get the expected exception when the time at which the counter is requested is invalid. */
    public function testCounterAt2(): void
    {
        $this->expectException(InvalidTimeException::class);
        $this->expectExceptionMessage("The time at which the counter was requested is before the reference time");

        $totp = self::createTotp(referenceTime: 120);
        $totp->counterAt(60);
    }

    /** Data provider with hash algorithms and reference times for testCounter1(). */
    public static function providerTestCounter1(): iterable
    {
        // current timestamp: 2025-10-14T16:00:00.000Z
        yield "sha1-6digit-1970" => [HashAlgorithm::Sha1Algorithm, 0, 1760457600, 58681920,];
        yield "sha256-6digit-1970" => [HashAlgorithm::Sha256Algorithm, 0, 1760457600, 58681920,];
        yield "sha512-6digit-1970" => [HashAlgorithm::Sha512Algorithm, 0, 1760457600, 58681920,];
        yield "sha1-6digit-1974" => [HashAlgorithm::Sha1Algorithm, new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC")), 1760457600, 54151680,];
        yield "sha256-6digit-1974" => [HashAlgorithm::Sha256Algorithm, new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC")), 1760457600, 54151680,];
        yield "sha512-6digit-1974" => [HashAlgorithm::Sha512Algorithm, new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC")), 1760457600, 54151680,];
    }

    /**
     * Ensure we get the correct counter based on the reference time.
     *
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor, Totp::counter() and Totp::counterAt() should not
     * throw with test data.
     */
    #[DataProvider("providerTestCounter1")]
    public function testCounter1(string $algorithm, int|DateTime $referenceTime, int $currentTimestamp, int $expectedCounter): void
    {
        $totp = self::createTotp(referenceTime: $referenceTime, hashAlgorithm: $algorithm);
        Mokkd::func("time")->returning($currentTimestamp);
        self::assertSame($expectedCounter, $totp->counter());
    }

    /** Data provider with timestamps and the expected counter bytes at those timestamps for testCounterBytesAt1(). */
    public static function providerTestCounterBytesAt1(): iterable
    {
        // test data from RFC 6238
        yield [59, "\x00\x00\x00\x00\x00\x00\x00\x01",];
        yield [1111111109, "\x00\x00\x00\x00\x02\x35\x23\xEC",];
        yield [1111111111, "\x00\x00\x00\x00\x02\x35\x23\xED",];
        yield [1234567890, "\x00\x00\x00\x00\x02\x73\xEF\x07",];
        yield [2000000000, "\x00\x00\x00\x00\x03\xF9\x40\xAA",];
        yield [20000000000, "\x00\x00\x00\x00\x27\xBC\x86\xAA",];

        // test data for non-default reference time
        yield [119, "\x00\x00\x00\x00\x00\x00\x00\x01", 60,];
        yield [121, "\x00\x00\x00\x00\x00\x00\x00\x02", 60,];

        // test data for non-default time step time
        yield [59, "\x00\x00\x00\x00\x00\x00\x00\x05", null, 10,];
        yield [61, "\x00\x00\x00\x00\x00\x00\x00\x06", null, 10,];

        // test data for non-default time step and non-default reference time
        yield [119, "\x00\x00\x00\x00\x00\x00\x00\x05", 60, 10,];
        yield [121, "\x00\x00\x00\x00\x00\x00\x00\x06", 60, 10,];
    }

    /** Ensure we get the correct bytes from counterBytesAt(). */
    #[DataProvider("providerTestCounterBytesAt1")]
    public function testCounterBytesAt1(int|DateTime $currentTime, string $expectedBytes, int|DateTime|null $referenceTime = null, ?int $timeStep = null): void
    {
        $totp = self::createTotp(referenceTime: $referenceTime ?? 0, timeStep: $timeStep ?? 30);

        $actualBytes = (new XRay($totp))->counterBytesAt($currentTime);
        self::assertSame($expectedBytes, $actualBytes, "The counter is expected to be " . self::hexOf($expectedBytes) . " but is actually " . self::hexOf($actualBytes) . ".");
    }

    /**
     * Test data for the counterBytes() method.
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public static function providerTestCounterBytes1(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        return [
            "sha1-6digit-1970" => [HashAlgorithm::Sha1Algorithm, 0, 1760457600, "\x00\x00\x00\x00\x03\x7fj@",],
            "sha256-6digit-1970" => [HashAlgorithm::Sha256Algorithm, 0, 1760457600, "\x00\x00\x00\x00\x03\x7fj@",],
            "sha512-6digit-1970" => [HashAlgorithm::Sha512Algorithm, 0, 1760457600, "\x00\x00\x00\x00\x03\x7fj@",],
            "sha1-6digit-1974" => [HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))), 1760457600, "\x00\x00\x00\x00\x03:J\x00",],
            "sha256-6digit-1974" => [HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))), 1760457600, "\x00\x00\x00\x00\x03:J\x00",],
            "sha512-6digit-1974" => [HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))), 1760457600, "\x00\x00\x00\x00\x03:J\x00",],
        ];
    }

    /**
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor should not throw with test data.
     */
    #[DataProvider("providerTestCounterBytes1")]
    public function testCounterBytes1(string $algorithm, int|DateTime $referenceTime, int $currentTimestamp, string $expectedBytes): void
    {
        $totp = self::createTotp(
            referenceTime: $referenceTime,
            hashAlgorithm: $algorithm,
        );

        Mokkd::func("time")->returning($currentTimestamp);
        self::assertSame($expectedBytes, (new XRay($totp))->counterBytes(), "The generated counter bytes did not match the expected counter bytes.");
    }

    /**
     * Test data for the password() method.
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public static function providerTestHmac1(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        return [
            "sha1-6digit-1970" => [],
            "sha1-7digit-1970" => [null, 7,],
            "sha1-8digit-1970" => [null, 8,],
            "sha256-6digit-1970" => [null, 6, HashAlgorithm::Sha256Algorithm,],
            "sha256-7digit-1970" => [null, 7, HashAlgorithm::Sha256Algorithm,],
            "sha256-8digit-1970" => [null, 8, HashAlgorithm::Sha256Algorithm,],
            "sha512-6digit-1970" => [null, 6, HashAlgorithm::Sha512Algorithm,],
            "sha512-7digit-1970" => [null, 7, HashAlgorithm::Sha512Algorithm,],
            "sha512-8digit-1970" => [null, 8, HashAlgorithm::Sha512Algorithm,],
            "sha1-6digit-1974" => [null, 6, HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha1-7digit-1974" => [null, 7, HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha1-8digit-1974" => [null, 8, HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha256-6digit-1974" => [null, 6, HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha256-7digit-1974" => [null, 7, HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha256-8digit-1974" => [null, 8, HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha512-6digit-1974" => [null, 6, HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha512-7digit-1974" => [null, 7, HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha512-8digit-1974" => [null, 8, HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
        ];
    }

    /**
     * Test for Totp::hmac().
     *
     * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
     * @param int $digits The number of digits for the password. Defaults to 6.
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor, hmac() and hmacAt() should not throw with
     * test data.
     */
    #[DataProvider("providerTestHmac1")]
    public function testHmac1(?string $secret = null, int $digits = 6, string $algorithm = HashAlgorithm::Sha1Algorithm, int|DateTime $referenceTime = 0): void
    {
        // The logic behind this test is this: password() can't return a pre-known value because it produces a
        // password dependent on an external factor - the current system time. So we use passwordAt() as our source of
        // expectations on the assumption that it provides a correct value. It's safe to do this because we have a test
        // for passwordAt() and that test will tell us if it's not working. In order mitigate against the outside chance
        // that the system time ticks over to the next TOTP time step between the point in time at which we call
        // time() and the point in time at which we fetch the actual password from the Totp object, we ensure that
        // the time after retrieving the password from the Totp object is the same as the time we're using as our
        // source of expectation.
        //
        // Note that while debugging, if you put a breakpoint on the call to Totp::password() you are more likely
        // to trigger a repeat of the loop
        /** @noinspection PhpUnhandledExceptionInspection Digits constructor should not throw with test data. */
        $totp = self::createTotp(
            $secret ?? self::TestSecret,
            new Integer(new Digits($digits)),
            $referenceTime,
            hashAlgorithm: $algorithm,
        );

        // unless you've set a breakpoint we should traverse this loop no more than twice
        do {
            $time = time();
            /** @noinspection PhpUnhandledExceptionInspection hmac() should not throw with test data. */
            $actual = $totp->hmac();
            $repeat = (time() !== $time);
        } while ($repeat);

        /** @noinspection PhpUnhandledExceptionInspection hmacAt() should not throw with test data. */
        $expected = $totp->hmacAt($time);
        self::assertSame($expected, $actual, "The generated HMAC did not match the expected HMAC.");
    }

    /**
     * Test data for testHmacAt().
     *
     * @return iterable The test data.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function providerTestHmacAt1(): iterable
    {
        // transform the RFC test data into the args required for testHmacAt()
        foreach (Rfc6238TestData::rfcTestData() as $testData) {
            yield [$testData["secret"]["raw"], 0, $testData["timestamp"], $testData["hmac"], $testData["algorithm"],];
        }

        // test for times before TOTP reference time
        yield [self::randomValidSecret(20), 120, 1, "", HashAlgorithm::Sha1Algorithm, InvalidTimeException::class,];
        yield [self::randomValidSecret(32), 120, 1, "", HashAlgorithm::Sha256Algorithm, InvalidTimeException::class,];
        yield [self::randomValidSecret(64), 120, 1, "", HashAlgorithm::Sha512Algorithm, InvalidTimeException::class,];
    }

    /**
     * Test for Totp::hmacAt()
     *
     * Tests the HMACs generated as part of the TOTP process.
     *
     * @param string $secret The TOTP secret.
     * @param int|\DateTime $referenceTime The TOTP reference time.
     * @param int|\DateTime $currentTime The time at which to test the password.
     * @param string $hmac The expected HMAC as a raw byte array.
     * @param string|null $algorithm The hash algorithm for the TOTP.
     * @param class-string|null $exceptionClass The class name of the exception expected to be thrown, if any.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::hmacAt() shouldn't throw unless we're expecting a test
     *     exception.
     */
    #[DataProvider("providerTestHmacAt1")]
    public function testHmacAt1(string $secret, int|DateTime $referenceTime, int|DateTime $currentTime, string $hmac, ?string $algorithm = HashAlgorithm::Sha1Algorithm, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection Constructor should not throw with test data. */
        $totp = (new Factory(timeStep: new TimeStep(30), referenceTime: $referenceTime, hashAlgorithm: new HashAlgorithm($algorithm)))->totp(Secret::fromRaw($secret));
        /** @noinspection PhpUnhandledExceptionInspection Totp::hmacAt() shouldn't throw unless we're expecting a test exception. */
        self::assertSame(
            $hmac,
            $totp->hmacAt($currentTime),
            "Unexpected HMAC at " .
            ($currentTime instanceof DateTime ? $currentTime : new DateTime("@{$currentTime}"))->format("Y-m-d H:i:s") .
            " with secret '" . self::hexOf($secret) . "', algorithm {$totp->hashAlgorithm()}, reference time " .
            $totp->referenceTime()->format("Y-m-d H:i:s") . ", time step {$totp->timeStep()}"
        );
    }

    /**
     * Test data for the password() method.
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public static function providerTestPassword1(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        return [
            "sha1-6digit-1970" => [],
            "sha1-7digit-1970" => [null, 7,],
            "sha1-8digit-1970" => [null, 8,],
            "sha256-6digit-1970" => [null, 6, HashAlgorithm::Sha256Algorithm,],
            "sha256-7digit-1970" => [null, 7, HashAlgorithm::Sha256Algorithm,],
            "sha256-8digit-1970" => [null, 8, HashAlgorithm::Sha256Algorithm,],
            "sha512-6digit-1970" => [null, 6, HashAlgorithm::Sha512Algorithm,],
            "sha512-7digit-1970" => [null, 7, HashAlgorithm::Sha512Algorithm,],
            "sha512-8digit-1970" => [null, 8, HashAlgorithm::Sha512Algorithm,],
            "sha1-6digit-1974" => [null, 6, HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha1-7digit-1974" => [null, 7, HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha1-8digit-1974" => [null, 8, HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha256-6digit-1974" => [null, 6, HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha256-7digit-1974" => [null, 7, HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha256-8digit-1974" => [null, 8, HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha512-6digit-1974" => [null, 6, HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha512-7digit-1974" => [null, 7, HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha512-8digit-1974" => [null, 8, HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
        ];
    }

    /**
     * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
     * @param int $digits The number of digits for the password. Defaults to 6.
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor and Integer renderer constructor should not throw
     * with test data. Totp::password() and Totp::passwordAt() should not throw with test data.
     */
    #[DataProvider("providerTestPassword1")]
    public function testPassword1(?string $secret = null, int $digits = 6, string $algorithm = HashAlgorithm::Sha1Algorithm, int|DateTime $referenceTime = 0): void
    {
        // The logic behind this test is this: password() can't return a pre-known value because it produces a
        // password dependent on an external factor - the current system time. So we use passwordAt() as our source of
        // expectations on the assumption that it provides a correct value. It's safe to do this because we have a test
        // for passwordAt() and that test will tell us if it's not working. In order mitigate against the outside chance
        // that the system time ticks over to the next TOTP time step between the point in time at which we call
        // time() and the point in time at which we fetch the actual password from the Totp object, we ensure that
        // the time after retrieving the password from the Totp object is the same as the time we're using as our
        // source of expectation.
        //
        // Note that while debugging, if you put a breakpoint on the call to Totp::password() you are more likely
        // to trigger a repeat of the loop
        /** @noinspection PhpUnhandledExceptionInspection Digits constructor should not throw with test data. */
        $totp = self::createTotp(
            secret: $secret ?? self::TestSecret,
            renderer: new Integer(new Digits($digits)),
            referenceTime: $referenceTime,
            hashAlgorithm: $algorithm,
        );

        // unless you've set a breakpoint we should traverse this loop no more than twice
        do {
            $time = time();
            /** @noinspection PhpUnhandledExceptionInspection password() should not throw with test data. */
            $actual = $totp->password();
            $repeat = (time() !== $time);
        } while ($repeat);

        /** @noinspection PhpUnhandledExceptionInspection passwordAt() should not throw with test data. */
        $expected = $totp->passwordAt($time);
        self::assertSame($expected, $actual, "The generated password did not match the expected password.");
    }

    /**
     * Test data for testPasswordAt().
     *
     * @return iterable The test data.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function providerTestPasswordAt1(): iterable
    {
        // transform the RFC test data into the args required for testPasswordAt()
        foreach (Rfc6238TestData::rfcTestData() as $testData) {
            yield [$testData["secret"]["raw"], 0, $testData["timestamp"], $testData["passwords"]["8"], $testData["algorithm"],];
        }

        // test for times before TOTP reference time
        yield [self::randomValidSecret(20), 120, 1, "", HashAlgorithm::Sha1Algorithm, InvalidTimeException::class,];
        yield [self::randomValidSecret(32), 120, 1, "", HashAlgorithm::Sha256Algorithm, InvalidTimeException::class,];
        yield [self::randomValidSecret(64), 120, 1, "", HashAlgorithm::Sha512Algorithm, InvalidTimeException::class,];
    }

    /**
     * Tests the generated passwords. The provided password is expected to be 8 digits. It will be tested with Integer
     * renderers of 8, 7 and 6 digits using a substring of the password where appropriate.
     *
     * @param string $secret The TOTP secret.
     * @param int|\DateTime $referenceTime The TOTP reference time.
     * @param int|\DateTime $currentTime The time at which to test the password.
     * @param string $password The 8 digits of the expected password.
     * @param string|null $algorithm The hash algorithm for the TOTP.
     * @param class-string|null $exceptionClass The class name of the exception expected to be thrown, if any.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor should not throw with test data. Integer renderer
     * constructor and setDigits() won't throw with known valid $digits used here. Totp::passwordAt() should only throw
     * expected test exceptions
     */
    #[DataProvider("providerTestPasswordAt1")]
    public function testPasswordAt1(string $secret, int|DateTime $referenceTime, int|DateTime $currentTime, string $password, ?string $algorithm = HashAlgorithm::Sha1Algorithm, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection Digits constructor does not throw with 8. */
        $renderer = new Integer(new Digits(8));

        $totp = self::createTotp(
            secret: $secret,
            renderer: $renderer,
            referenceTime: $referenceTime,
            hashAlgorithm: $algorithm,
        );

        /** @noinspection PhpUnhandledExceptionInspection passwordAt() should only throw expected test exceptions. */
        self::assertSame(
            $password,
            $totp->passwordAt($currentTime),
            "Unexpected password at " .
            ($currentTime instanceof DateTime ? $currentTime : new DateTime("@{$currentTime}"))->format("Y-m-d H:i:s") .
            " with secret '" . self::hexOf($secret) . "', algorithm {$totp->hashAlgorithm()}, reference time " .
            $totp->referenceTime()->format("Y-m-d H:i:s") . ", time step {$totp->timeStep()}"
        );
    }

    /**
     * Test data for testVerify()
     *
     * @return iterable
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function providerTestVerify1(): iterable
    {
        // yield 100 random valid configurations for a Totp
        for ($idx = 0; $idx < 100; ++$idx) {
            yield "randomConfiguration" . sprintf("%02d", $idx) => [
                self::randomValidSecret(64),
                mt_rand(6, 8),
                match (mt_rand(0, 2)) {
                    0 => HashAlgorithm::Sha1Algorithm,
                    1 => HashAlgorithm::Sha256Algorithm,
                    2 => HashAlgorithm::Sha512Algorithm,
                },
                mt_rand(0, time() - 20 * 365 * 24 * 60 * 60),
            ];
        }
    }

    /**
     * @param string|null $secret The raw bytes of the TOTP secret. If null, a random secret will be chosen.
     * @param int $digits The number of digits for the password. Defaults to 6.
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor, Integer renderer constructor,
     * Totp::password() and Totp::verify() shouldn't throw with test data.
     */
    #[DataProvider("providerTestVerify1")]
    public function testVerify1(?string $secret = null, int $digits = 6, string $algorithm = HashAlgorithm::Sha1Algorithm, int|DateTime $referenceTime = 0): void
    {
        // The logic behind this test is this: verify() can't return a pre-known value because it is dependent on an
        // external factor - the current system time. So we fetch the current password, which we know should pass
        // verification, and verify that on the assumption that password() provides the correct value. It's
        // safe to do this because we have a test for password() and that test will tell us if it's not working.
        // In order mitigate against the outside chance that the system time ticks over to the next TOTP time step
        // between the point in time at which we call time() and the point in time at which we do the verification, we
        // ensure that the time after doing the verification is the same as the time before it, ensuring that we've
        // called verify at the same second as we fetched the password. We also change one digit of the password and
        // test with that as well, to ensure we have both positive and negative tests for verify().
        //
        // Note that while debugging, if you put a breakpoint on the call to Totp::verify() you are more likely
        // to trigger a repeat of the loop
        /** @noinspection PhpUnhandledExceptionInspection Totp constructor shouldn't throw with test data. Integer
         * renderer constructor shouldn't throw with test data.
         */
        $totp = (new Factory(renderer: new Integer(new Digits($digits)), referenceTime: $referenceTime, hashAlgorithm: new HashAlgorithm($algorithm)))->totp(Secret::fromRaw($secret));

        // unless you've set a breakpoint we should traverse this loop no more than twice
        do {
            $time = time();
            /** @noinspection PhpUnhandledExceptionInspection Shouldn't throw with test data. */
            $correctPassword = $totp->password();
            // change one digit of the correct password by one, making it incorrect
            $incorrectPassword    = $correctPassword;
            $incorrectPassword[3] = "" . ((intval($incorrectPassword[3]) + 1) % 10);
            /** @noinspection PhpUnhandledExceptionInspection Shouldn't throw with test data. */
            $correctPasswordVerified = $totp->verify($correctPassword);
            /** @noinspection PhpUnhandledExceptionInspection Shouldn't throw with test data. */
            $incorrectPasswordVerified = $totp->verify($incorrectPassword);
            $repeat                    = (time() !== $time);
        } while ($repeat);

        self::assertTrue($correctPasswordVerified, "Totp::verified() did not verify the correct password.");
        self::assertFalse($incorrectPasswordVerified, "Totp::verified() incorrectly verified the incorrect password.");
    }

    /**
     * Test data for testVerifyAt().
     *
     * @return iterable The test data.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function providerTestVerifyAt1(): iterable
    {
        // transforms the RFC data into the structure required for this test
        $extractData = static function (array $testData) use (&$digits, &$window): array {
            return [
                [
                    "secret" => $testData["secret"]["raw"],
                    "digits" => $digits,
                    "referenceTime" => $testData["referenceTimestamp"],
                    "time-step" => $testData["time-step"],
                    "hashAlgorithm" => $testData["algorithm"],
                ],
                // add time steps to the "current" time to ensure that the password at the oldest time step within the
                // window is the one that is expected to match the password
                $testData["timestamp"] + ($window * $testData["time-step"]),
                $window,
                $testData["passwords"]["{$digits}"],
                true,
            ];
        };

        for ($window = 0; $window < 3; ++$window) {
            for ($digits = 6; $digits <= 8; ++$digits) {
                foreach (Rfc6238TestData::rfcTestData() as $key => $value) {
                    yield "{$key}-{$digits}-{$window}" => $extractData($value);
                }
            }
        }

        yield from [
            "emptyPassword6digitsSha1" => [["secret" => self::randomValidSecret(20), "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "", false,],
            "emptyPassword6digitsSha256" => [["secret" => self::randomValidSecret(32), "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "", false,],
            "emptyPassword6digitsSha512" => [["secret" => self::randomValidSecret(64), "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "", false,],

            "emptyPassword7digitsSha1" => [["secret" => self::randomValidSecret(20), "digits" => 7, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "", false,],
            "emptyPassword7digitsSha256" => [["secret" => self::randomValidSecret(32), "digits" => 7, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "", false,],
            "emptyPassword7digitsSha512" => [["secret" => self::randomValidSecret(64), "digits" => 7, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "", false,],

            "emptyPassword8digitsSha1" => [["secret" => self::randomValidSecret(20), "digits" => 8, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "", false,],
            "emptyPassword8digitsSha256" => [["secret" => self::randomValidSecret(32), "digits" => 8, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "", false,],
            "emptyPassword8digitsSha512" => [["secret" => self::randomValidSecret(64), "digits" => 8, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "", false,],

            "alphaPassword6digitsSha1" => [["secret" => self::randomValidSecret(20), "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "ABCDEF", false,],
            "alphaPassword6digitsSha256" => [["secret" => self::randomValidSecret(32), "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "ABCDEF", false,],
            "alphaPassword6digitsSha512" => [["secret" => self::randomValidSecret(64), "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "ABCDEF", false,],

            "alphaPassword7digitsSha1" => [["secret" => self::randomValidSecret(20), "digits" => 7, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "ABCDEFG", false,],
            "alphaPassword7digitsSha256" => [["secret" => self::randomValidSecret(32), "digits" => 7, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "ABCDEFG", false,],
            "alphaPassword7digitsSha512" => [["secret" => self::randomValidSecret(64), "digits" => 7, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "ABCDEFG", false,],

            "alphaPassword8digitsSha1" => [["secret" => self::randomValidSecret(20), "digits" => 8, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "ABCDEFGH", false,],
            "alphaPassword8digitsSha256" => [["secret" => self::randomValidSecret(32), "digits" => 8, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "ABCDEFGH", false,],
            "alphaPassword8digitsSha512" => [["secret" => self::randomValidSecret(64), "digits" => 8, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "ABCDEFGH", false,],

            // RFC data with one digit in the password changed by 1
            "numericPassword6digitsSha1Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "287081", false,],
            "numericPassword6digitsSha256Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "247375", false,],
            "numericPassword6digitsSha512Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "342146", false,],

            "numericPassword6digitsSha1Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "287072", false,],
            "numericPassword6digitsSha256Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "247364", false,],
            "numericPassword6digitsSha512Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "342137", false,],

            "numericPassword6digitsSha1Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "287182", false,],
            "numericPassword6digitsSha256Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "247474", false,],
            "numericPassword6digitsSha512Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "342247", false,],

            "numericPassword6digitsSha1Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "288082", false,],
            "numericPassword6digitsSha256Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "248374", false,],
            "numericPassword6digitsSha512Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "343147", false,],

            "numericPassword6digitsSha1Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "277082", false,],
            "numericPassword6digitsSha256Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "237374", false,],
            "numericPassword6digitsSha512Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "332147", false,],

            "numericPassword6digitsSha1Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "187082", false,],
            "numericPassword6digitsSha256Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "147374", false,],
            "numericPassword6digitsSha512Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "242147", false,],

            "numericPassword7digitsSha1Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "4287083", false,],
            "numericPassword7digitsSha256Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "2247375", false,],
            "numericPassword7digitsSha512Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "9342146", false,],

            "numericPassword7digitsSha1Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "4287092", false,],
            "numericPassword7digitsSha256Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "2247384", false,],
            "numericPassword7digitsSha512Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "9342157", false,],

            "numericPassword7digitsSha1Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "4287182", false,],
            "numericPassword7digitsSha256Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "2247274", false,],
            "numericPassword7digitsSha512Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "9342047", false,],

            "numericPassword7digitsSha1Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "4288082", false,],
            "numericPassword7digitsSha256Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "2248374", false,],
            "numericPassword7digitsSha512Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "9343147", false,],

            "numericPassword7digitsSha1Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "4297082", false,],
            "numericPassword7digitsSha256Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "2257374", false,],
            "numericPassword7digitsSha512Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "9352147", false,],

            "numericPassword7digitsSha1Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "4187082", false,],
            "numericPassword7digitsSha256Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "2147374", false,],
            "numericPassword7digitsSha512Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "9242147", false,],

            "numericPassword7digitsSha1Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "3287082", false,],
            "numericPassword7digitsSha256Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "1247374", false,],
            "numericPassword7digitsSha512Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "8342147", false,],

            "numericPassword8digitsSha1Digit8Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "94287083", false,],
            "numericPassword8digitsSha256Digit8Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "32247375", false,],
            "numericPassword8digitsSha512Digit8Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "69342148", false,],

            "numericPassword8digitsSha1Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "94287092", false,],
            "numericPassword8digitsSha256Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "32247384", false,],
            "numericPassword8digitsSha512Digit7Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "69342157", false,],

            "numericPassword8digitsSha1Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "94287182", false,],
            "numericPassword8digitsSha256Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "32247474", false,],
            "numericPassword8digitsSha512Digit6Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "69342247", false,],

            "numericPassword8digitsSha1Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "94286082", false,],
            "numericPassword8digitsSha256Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "32246374", false,],
            "numericPassword8digitsSha512Digit5Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "69343147", false,],

            "numericPassword8digitsSha1Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "94297082", false,],
            "numericPassword8digitsSha256Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "32257374", false,],
            "numericPassword8digitsSha512Digit4Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "69352147", false,],

            "numericPassword8digitsSha1Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "94387082", false,],
            "numericPassword8digitsSha256Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "32347374", false,],
            "numericPassword8digitsSha512Digit3Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "69242147", false,],

            "numericPassword8digitsSha1Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "95287082", false,],
            "numericPassword8digitsSha256Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "31247374", false,],
            "numericPassword8digitsSha512Digit2Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "68342147", false,],

            "numericPassword8digitsSha1Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "2287082", false,],
            "numericPassword8digitsSha256Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 0, "0247374", false,],
            "numericPassword8digitsSha512Digit1Wrong" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha512Algorithm,], 59, 0, "7342147", false,],

            // time specified as DateTime
            "currentTimeAsDateTime01" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], new DateTime("@59", new DateTimeZone("UTC")), 0, "287082", true,],
            "currentTimeAsDateTime02" => [["secret" => "12345678901234567890", "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], new DateTime("@59", new DateTimeZone("UTC")), 0, "287072", false,],

            // invalid window
            "invalidWindowMinus1" => [["secret" => self::randomValidSecret(20), "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, -1, "", false, InvalidVerificationWindowException::class,],
            "invalidWindowBeyondReferenceTime" => [["secret" => self::randomValidSecret(32), "digits" => 6, "referenceTime" => 0, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha256Algorithm,], 59, 2, "", false, InvalidVerificationWindowException::class,],

            // invalid "current" time
            "invalidTime" => [["secret" => self::randomValidSecret(20), "digits" => 6, "referenceTime" => 240, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 59, 0, "", false, InvalidTimeException::class,],
            "marginallyInvalidTime" => [["secret" => self::randomValidSecret(20), "digits" => 6, "referenceTime" => 240, "time-step" => 30, "hashAlgorithm" => HashAlgorithm::Sha1Algorithm,], 239, 0, "", false, InvalidTimeException::class,],
        ];
    }

    /**
     * @param array $totpSpec The values to use to initialise the Totp object.
     * @param int|\DateTime $currentTime The timestamp at which to check verification.
     * @param int $window The verification window, expressed in time steps.
     * @param string $userPassword The password to verify.
     * @param bool $expectedVerification Whether Totp::verifyAt() should verify the password at the time.
     * @param class-string|null $exceptionClass The class name of an exception expected to be thrown, if any.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::integer() shouldn't throw with test data. Totp::verifyAt()
     * won't throw unless we're expecting a test exception.
     */
    #[DataProvider("providerTestVerifyAt1")]
    public function testVerifyAt1(array $totpSpec, int|DateTime $currentTime, int $window, string $userPassword, bool $expectedVerification, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection Digits constructor shouldn't throw with test data. */
        $totp = self::createTotp(
            $totpSpec["secret"],
            new Integer(new Digits($totpSpec["digits"])),
            $totpSpec["referenceTime"],
            $totpSpec["time-step"],
            $totpSpec["hashAlgorithm"],
        );

        /** @noinspection PhpUnhandledExceptionInspection Totp::verifyAt() won't throw unless we're expecting a test
         * exception.
         */
        self::assertEquals($expectedVerification, $totp->verifyAt(password: $userPassword, time: $currentTime, window: $window), "Verification not as expected.");
    }
}
