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
use CitrusLab\Totp\Exceptions\SecureRandomDataUnavailableException;
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Renderers\EightDigits;
use CitrusLab\Totp\Renderers\Integer;
use CitrusLab\Totp\Renderers\SixDigits;
use CitrusLab\Totp\Renderers\Steam;
use CitrusLab\Totp\Types\Digits;
use CitrusLab\Totp\Types\HashAlgorithm;
use CitrusLab\Totp\Types\Secret;
use CitrusLab\Totp\Types\TimeStep;
use CitrusLab\TotpTests\Framework\TestCase;
use DateTime;
use DateTimeZone;
use Equit\XRay\StaticXRay;
use Exception;
use Mokkd;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(Factory::class)]
final class FactoryTest extends TestCase
{
    protected function tearDown(): void
    {
        Mokkd::close();
    }

    /** Helper to create a "vanilla" Factory test instance. */
    protected static function createFactory(): Factory
    {
        return new Factory();
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


    /** Ensure the default-constructed factory has the expected specification. */
    public function testConstructor1(): void
    {
        $factory = new Factory();
        self::assertInstanceOf(SixDigits::class, $factory->renderer());
        self::assertSame(0, $factory->referenceTimestamp());
        self::assertEquals(new DateTime("@0", new DateTimeZone("UTC")), $factory->referenceTime());
        self::assertEquals(new TimeStep(30), $factory->timeStep());
        self::assertEquals(new HashAlgorithm(HashAlgorithm::Sha1Algorithm), $factory->hashAlgorithm());
    }

    /** Ensure the constructor sets the renderer. */
    public function testConstructor2(): void
    {
        $renderer = new Steam();
        $factory  = new Factory($renderer);
        self::assertSame($renderer, $factory->renderer());
        self::assertSame(0, $factory->referenceTimestamp());
        self::assertEquals(new DateTime("@0", new DateTimeZone("UTC")), $factory->referenceTime());
        self::assertEquals(new TimeStep(30), $factory->timeStep());
        self::assertEquals(HashAlgorithm::sha1(), $factory->hashAlgorithm());
    }

    /** Ensure the constructor sets the time step. */
    public function testConstructor3(): void
    {
        $timeStep = new TimeStep(60);
        $factory  = new Factory(timeStep: $timeStep);
        self::assertInstanceOf(SixDigits::class, $factory->renderer());
        self::assertSame(0, $factory->referenceTimestamp());
        self::assertEquals(new DateTime("@0", new DateTimeZone("UTC")), $factory->referenceTime());
        self::assertSame($timeStep, $factory->timeStep());
        self::assertEquals(HashAlgorithm::sha1(), $factory->hashAlgorithm());
    }

    /** Ensure the constructor sets the reference time from a Unix timestamp. */
    public function testConstructor4(): void
    {
        $factory = new Factory(referenceTime: 60);
        self::assertInstanceOf(SixDigits::class, $factory->renderer());
        self::assertSame(60, $factory->referenceTimestamp());
        self::assertEquals(new DateTime("@60", new DateTimeZone("UTC")), $factory->referenceTime());
        self::assertEquals(new TimeStep(30), $factory->timeStep());
        self::assertEquals(HashAlgorithm::sha1(), $factory->hashAlgorithm());
    }

    /** Ensure the constructor sets the reference time from a DateTime instance. */
    public function testConstructor5(): void
    {
        // 2000-01-01T00:00:00.000Z
        $referenceTime = new DateTime("@946684800", new DateTimeZone("UTC"));
        $factory       = new Factory(referenceTime: $referenceTime);
        self::assertInstanceOf(SixDigits::class, $factory->renderer());
        self::assertSame(946684800, $factory->referenceTimestamp());
        self::assertEquals($referenceTime, $factory->referenceTime());
        self::assertEquals(new TimeStep(30), $factory->timeStep());
        self::assertEquals(HashAlgorithm::sha1(), $factory->hashAlgorithm());
    }

    /** Ensure the constructor sets the hash algorithm. */
    public function testConstructor6(): void
    {
        $algorithm = HashAlgorithm::sha512();
        $factory   = new Factory(hashAlgorithm: $algorithm);
        self::assertInstanceOf(SixDigits::class, $factory->renderer());
        self::assertSame(0, $factory->referenceTimestamp());
        self::assertEquals(new DateTime("@0", new DateTimeZone("UTC")), $factory->referenceTime());
        self::assertEquals(new TimeStep(30), $factory->timeStep());
        self::assertSame($algorithm, $factory->hashAlgorithm());
    }

    /**
     * Data provider with TOTP specifications for testSixDigits1().
     *
     * @return iterable The RFC test data mapped to the correct structure for the test arguments.
     */
    public static function providerTestSixDigits1(): iterable
    {
        foreach (Rfc6238TestData::rfcTestData() as $testData) {
            yield [
                $testData["secret"]["raw"],
                $testData["time-step"],
                $testData["referenceTimestamp"],
                $testData["algorithm"],
            ];
        }
    }

    /**
     * Ensure the sixDigits() factory method provides the expected Totp calculator.
     *
     * @param string $secret The secret for the Totp.
     * @param int $timeStep The time step for the Totp.
     * @param int|\DateTime $referenceTime The reference time for the Totp.
     * @param string $hashAlgorithm The hash algorithm for the Totp.
     *
     * @noinspection PhpDocMissingThrowsInspection The test data should not cause any exceptions to be thrown.
     */
    #[DataProvider("providerTestSixDigits1")]
    public function testSixDigits1(string $secret, int $timeStep = TimeStep::DefaultTimeStep, int|DateTime $referenceTime = Factory::DefaultReferenceTime, string $hashAlgorithm = HashAlgorithm::DefaultAlgorithm): void
    {
        /** @noinspection PhpUnhandledExceptionInspection Only throws if we're expecting a test exception */
        $factory = Factory::sixDigits(timeStep: new TimeStep($timeStep), referenceTime: $referenceTime, hashAlgorithm: new HashAlgorithm($hashAlgorithm))->totp(Secret::fromRaw($secret));
        self::assertEquals($secret, $factory->secret(), "Secret in Totp object does not match expected secret.");
        self::assertEquals($timeStep, $factory->timeStep()->seconds(), "TimeStep in Totp object does not match expected time step.");
        self::assertEquals($hashAlgorithm, $factory->hashAlgorithm()->algorithm(), "Hash algorithm in Totp object does not match expected algorithm.");

        if ($referenceTime instanceof DateTime) {
            $referenceTimestamp = $referenceTime->getTimestamp();
        } else {
            $referenceTimestamp = $referenceTime;
            /** @noinspection PhpUnhandledExceptionInspection Constructor doesn't throw with timestamp. */
            $referenceTime = new DateTime("@{$referenceTime}", new DateTimeZone("UTC"));
        }

        self::assertEquals($referenceTime, $factory->referenceTime(), "Reference DateTime in Totp object does not match expected DateTime.");
        self::assertEquals($referenceTimestamp, $factory->referenceTimestamp(), "Reference timestamp in Totp object does not match expected timestamp.");

        $renderer = $factory->renderer();
        self::assertInstanceOf(SixDigits::class, $renderer, "The Totp does not have the expected renderer type.");
        self::assertEquals(6, $renderer->digits()->quantity(), "The Totp renderer does not use the expected number of digits.");
    }

    /**
     * Data provider with TOTP specifications for testEightDigits1().
     *
     * @return iterable The RFC test data mapped to the correct arrangement for the test arguments.
     */
    public static function providerTestEightDigits1(): iterable
    {
        foreach (Rfc6238TestData::rfcTestData() as $testData) {
            yield [
                $testData["secret"]["raw"],
                $testData["time-step"],
                $testData["referenceTimestamp"],
                $testData["algorithm"],
            ];
        }
    }

    /**
     * Ensure the eightDigits() factory method provides the expected Totp calculator.
     *
     * @param string $secret The secret for the Totp.
     * @param int $timeStep The time step for the Totp.
     * @param int|\DateTime $referenceTime The reference time for the Totp.
     * @param string $hashAlgorithm The hash algorithm for the Totp.
     *
     * @noinspection PhpDocMissingThrowsInspection The test data should not cause any exceptions to be thrown.
     */
    #[DataProvider("providerTestEightDigits1")]
    public function testEightDigits1(string $secret, int $timeStep = TimeStep::DefaultTimeStep, int|DateTime $referenceTime = Factory::DefaultReferenceTime, string $hashAlgorithm = HashAlgorithm::DefaultAlgorithm): void
    {
        /** @noinspection PhpUnhandledExceptionInspection Only throws if we're expecting a test exception */
        $factory = Factory::eightDigits(timeStep: new TimeStep($timeStep), referenceTime: $referenceTime, hashAlgorithm: new HashAlgorithm($hashAlgorithm))->totp(Secret::fromRaw($secret));
        self::assertEquals($secret, $factory->secret(), "Secret in Totp object does not match expected secret.");
        self::assertEquals($timeStep, $factory->timeStep()->seconds(), "Time step in Totp object does not match expected time step.");
        self::assertEquals($hashAlgorithm, $factory->hashAlgorithm()->algorithm(), "Hash algorithm in Totp object does not match expected algorithm.");

        if ($referenceTime instanceof DateTime) {
            $referenceTimestamp = $referenceTime->getTimestamp();
        } else {
            $referenceTimestamp = $referenceTime;
            /** @noinspection PhpUnhandledExceptionInspection Constructor doesn't throw with timestamp. */
            $referenceTime = new DateTime("@{$referenceTime}", new DateTimeZone("UTC"));
        }

        self::assertEquals($referenceTime, $factory->referenceTime(), "Reference DateTime in Totp object does not match expected DateTime.");
        self::assertEquals($referenceTimestamp, $factory->referenceTimestamp(), "Reference timestamp in Totp object does not match expected timestamp.");

        $renderer = $factory->renderer();
        self::assertInstanceOf(EightDigits::class, $renderer, "The Totp does not have the expected renderer type.");
        self::assertEquals(8, $renderer->digits()->quantity(), "The Totp renderer does not use the expected number of digits.");
    }

    /**
     * Data provider with TOTP specifications for testInteger1().
     *
     * The test data consists of the RFC test data mapped to the correct structure for the test arguments, plus some
     * data to test specific scenarios, plus 100 random valid datasets.
     *
     * @return iterable The test data.
     */
    public static function providerTestInteger1(): iterable
    {
        foreach (Rfc6238TestData::rfcTestData() as $testData) {
            $core = [
                $testData["secret"]["raw"],
                $testData["time-step"],
                $testData["referenceTimestamp"],
                $testData["algorithm"],
            ];

            yield [8, ...$core];
            yield [7, ...$core];
            yield [6, ...$core];
        }
    }

    /**
     * Ensure the eightDigits() factory method provides the expected Totp calculator.
     *
     * @param mixed $digits The number of digits in generated passwords.
     * @param string $secret The secret for the Totp.
     * @param int $timeStep The time step for the Totp.
     * @param int|\DateTime $referenceTime The reference time for the Totp.
     * @param string $hashAlgorithm The hash algorithm for the Totp.
     *
     * @noinspection PhpDocMissingThrowsInspection The test data should not cause any exceptions to be thrown.
     */
    #[DataProvider("providerTestInteger1")]
    public function testInteger1(mixed $digits, string $secret, int $timeStep = TimeStep::DefaultTimeStep, int|DateTime $referenceTime = Factory::DefaultReferenceTime, string $hashAlgorithm = HashAlgorithm::DefaultAlgorithm): void
    {
        /** @noinspection PhpUnhandledExceptionInspection Only throws if we're expecting a test exception */
        $factory = Factory::integer(digits: new Digits($digits), timeStep: new TimeStep($timeStep), referenceTime: $referenceTime, hashAlgorithm: new HashAlgorithm($hashAlgorithm))->totp(Secret::fromRaw($secret));
        self::assertEquals($secret, $factory->secret(), "Secret in Totp object does not match expected secret.");
        self::assertEquals($timeStep, $factory->timeStep()->seconds(), "Time step in Totp object does not match expected time step.");
        self::assertEquals($hashAlgorithm, $factory->hashAlgorithm()->algorithm(), "Hash algorithm in Totp object does not match expected algorithm.");

        if ($referenceTime instanceof DateTime) {
            $referenceTimestamp = $referenceTime->getTimestamp();
        } else {
            $referenceTimestamp = $referenceTime;
            /** @noinspection PhpUnhandledExceptionInspection Constructor doesn't throw with timestamp. */
            $referenceTime = new DateTime("@{$referenceTime}", new DateTimeZone("UTC"));
        }

        self::assertEquals($referenceTime, $factory->referenceTime(), "Reference DateTime in Totp object does not match expected DateTime.");
        self::assertEquals($referenceTimestamp, $factory->referenceTimestamp(), "Reference timestamp in Totp object does not match expected timestamp.");

        $renderer = $factory->renderer();
        self::assertInstanceOf(Integer::class, $renderer, "The Totp does not have the expected renderer type.");
        self::assertEquals($digits, $renderer->digits()->quantity(), "The Totp renderer does not use the expected number of digits.");
    }

    /**
     * Test data for testTotp1().
     *
     * @return array The test data.
     */
    public static function providerTestTotp1(): array
    {
        return [
            "typicalPlainText" => ["password-password", "OBQXG43XN5ZGILLQMFZXG53POJSA====",],
            "typicalBinary" => ["\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d", "CVYNPLS6RDRTYW2JY6U46JPTD7N2Z645",],
            "extremeBinaryZeroes" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",],
            "extremeBinaryOnes" => ["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "77777777777777777777777777777777",],
            "extremeLongBinary" => [
                "\x4d\x51\xa7\x96\x6f\x8f\xf6\xcb\x19\xb5\x61\x2f\xe8\x77\xa8\x78\x26\xb7\xcc\x92\x09\xa0\xe0\x6c\x1a\x8e\x99\x30\x61\x1c\xfc\x18\xd4\x9e\xae\x78\x0c\xc0\x5e\x73\x0c\xd5\x55\x25\x5b\x39\x2a\xd9\x64\x95\xf5\x36\xa5\xe8\x64\x06\xf0\x73\x58\xfc\xfa\x27\xd5\x15\xe5\xa9\x62\xce\x0c\x04\x1e\xa6\xbd\xbc\xde\x61\xb5\x95\xca\x42\x94\xb5\x1b\x1e\xe3\x8c\xde\x14\xb2\x8a\x00\x10\xd4\x96\xa8\xd0\x33\xf6\x7e\x85\xc4\x3e\x94\x5c\xe2\xe5\x6a\x24\x5a\x5e\x27\x2c\xd0\xed\xb0\x33\xe4\x4e\x1a\xcc",
                "JVI2PFTPR73MWGNVMEX6Q55IPATLPTESBGQOA3A2R2MTAYI47QMNJHVOPAGMAXTTBTKVKJK3HEVNSZEV6U3KL2DEA3YHGWH47IT5KFPFVFRM4DAED2TL3PG6MG2ZLSSCSS2RWHXDRTPBJMUKAAINJFVI2AZ7M7UFYQ7JIXHC4VVCIWS6E4WNB3NQGPSE4GWM",
            ],
        ];
    }

    /**
     * Ensure totp() generates Totp calculators with the expected secret.
     *
     * @param string $raw The raw secret.
     * @param string $base32 The expected Base32 for the raw secret.
     */
    #[DataProvider("providerTestTotp1")]
    public function testTotp1(string $raw, string $base32): void
    {
        $factory = self::createFactory();
        /** @noinspection PhpUnhandledExceptionInspection Secret::fromRaw() shouldn't throw with test data. */
        $totp = $factory->totp(Secret::fromRaw($raw));
        self::assertSame($base32, $totp->base32Secret(), "The base32 of the raw secret '" . self::hexOf($raw) . "' did not match the expected string.");
    }

    /** Data provider with valid hash algorithms. */
    public static function providerValidHashAlgorithms(): iterable
    {
        yield "sha-1" => [HashAlgorithm::Sha1Algorithm,];
        yield "sha-256" => [HashAlgorithm::Sha256Algorithm,];
        yield "sha-512" => [HashAlgorithm::Sha512Algorithm,];
    }

    /** Ensure the hash algorithm can be set immutably. */
    #[DataProvider("providerValidHashAlgorithms")]
    public function testWithHashAlgorithm1(string $algorithm): void
    {
        $factory = self::createFactory();
        self::assertSame(HashAlgorithm::Sha1Algorithm, $factory->hashAlgorithm()->algorithm(), "The default hash algorithm was expected to be " . HashAlgorithm::Sha1Algorithm . " but {$factory->hashAlgorithm()->algorithm()} was reported.");
        /** @noinspection PhpUnhandledExceptionInspection HashAlgorithm constructor shouldn't throw with test data. */
        $actual = $factory->withHashAlgorithm(new HashAlgorithm($algorithm));
        self::assertNotSame($factory, $actual);
        self::assertSame(HashAlgorithm::Sha1Algorithm, $factory->hashAlgorithm()->algorithm(), "The hash algorithm of the original factory was expected to remain " . HashAlgorithm::Sha1Algorithm . " but {$factory->hashAlgorithm()->algorithm()} was reported.");
        self::assertSame($algorithm, $actual->hashAlgorithm()->algorithm(), "The has algorithm was expected to be {$algorithm} but {$factory->hashAlgorithm()} was reported.");
    }

    /** Data provider with valid hash reference times. */
    public static function providerValidReferenceTimes(): iterable
    {
        // 1995-01-01T00:00:00.000Z
        yield "typicalEpochAsInt" => [788918400,];

        // 1980-01-01T00:00:00.000Z
        yield "typicalEpochAsDateTimeUtc" => [new DateTime("@315532800", new DateTimeZone("UTC")),];

        yield "typical10YearsAfterEpoch" => [self::yearsInSeconds(10),];
        yield "typical20YearsAfterEpoch" => [self::yearsInSeconds(20),];
        yield "typical30YearsAfterEpoch" => [self::yearsInSeconds(30),];
        yield "typical10SecondsAfterEpoch" => [self::daysInSeconds(10),];
        yield "typical20SecondsAfterEpoch" => [self::daysInSeconds(20),];
        yield "typical30SecondsAfterEpoch" => [self::daysInSeconds(30),];
        yield "typical40SecondsAfterEpoch" => [self::daysInSeconds(40),];
        yield "typical50SecondsAfterEpoch" => [self::daysInSeconds(50),];
        yield "typical60SecondsAfterEpoch" => [self::daysInSeconds(60),];
        yield "typical70SecondsAfterEpoch" => [self::daysInSeconds(70),];
        yield "typical80SecondsAfterEpoch" => [self::daysInSeconds(80),];
        yield "typical90SecondsAfterEpoch" => [self::daysInSeconds(90),];
        yield "typical100SecondsAfterEpoch" => [self::daysInSeconds(100),];

        yield "typicalDateTimeUtc" => [new DateTime("23-04-1974", new DateTimeZone("UTC")),];
        yield "typicalDateTimeUtc-4" => [new DateTime("28-01-1978", new DateTimeZone("-0400")),];
        yield "typicalDateTimeUtc+4" => [new DateTime("19-07-2000", new DateTimeZone("+0400")),];
        yield "typicalDateTimeUtc-6" => [new DateTime("04-03-1984", new DateTimeZone("-0600")),];
        yield "typicalDateTimeUtc+6" => [new DateTime("31-12-1999", new DateTimeZone("+0600")),];
    }

    /** Ensure the reference time can be set immutably. */
    #[DataProvider("providerValidReferenceTimes")]
    public function testWithReferenceTime1(int|DateTime $time): void
    {
        $factory = self::createFactory();
        self::assertSame(0, $factory->referenceTimestamp());
        $actual = $factory->withReferenceTime($time);
        self::assertNotSame($factory, $actual);
        self::assertSame(0, $factory->referenceTimestamp());

        if (is_int($time)) {
            $timestamp = $time;
            $time      = new DateTime("@{$timestamp}", new DateTimeZone("UTC"));
        } else {
            $timestamp = $time->getTimestamp();
        }

        self::assertSame($timestamp, $actual->referenceTimestamp());
        self::assertEquals($time, $actual->referenceTime());
    }

    /** Data provider with valid time steps. */
    public static function providerValidTimeSteps(): iterable
    {
        yield "typical30" => [30,];
        yield "typical60" => [60,];
        yield "typical10" => [10,];
        yield "typical20" => [20,];
    }

    /** Ensure the time-step can be set immutably. */
    #[DataProvider("providerValidTimeSteps")]
    public function testWithTimeStep1(mixed $timeStep): void
    {
        $factory = self::createFactory();
        self::assertSame(30, $factory->timeStep()->seconds());
        /** @noinspection PhpUnhandledExceptionInspection TimeStep constructor should not throw with test data. */
        $actual = $factory->withTimeStep(new TimeStep($timeStep));
        self::assertNotSame($factory, $actual);
        self::assertSame(30, $factory->timeStep()->seconds());
        self::assertSame($timeStep, $actual->timeStep()->seconds(), "The time step {$timeStep} was expected but {$factory->timeStep()->seconds()} was reported.");
    }

    /** Data provider with valid renderer instances. */
    public static function providerValidRenderers(): iterable
    {
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

    /** Ensure the renderer can be set immutably. */
    #[DataProvider("providerValidRenderers")]
    public function testWithRenderer1(mixed $renderer): void
    {
        $factory          = self::createFactory();
        $originalRenderer = $factory->renderer();
        $actual           = $factory->withRenderer($renderer);
        self::assertNotSame($factory, $actual, "withRenderer() did not clone the Factory");
        self::assertSame($originalRenderer, $factory->renderer(), "withRenderer() altered the original Factory instance's renderer");
        self::assertSame($renderer, $actual->renderer(), "withRenderer() did not set the clone's renderer");
    }

    /**
     * Test the defaultRenderer() method.
     */
    public function testDefaultRenderer(): void
    {
        $xray = new StaticXRay(Factory::class);
        self::assertInstanceOf(SixDigits::class, $xray->defaultRenderer());
    }

    /**
     * Test the randomSecret() method.
     * @throws \CitrusLab\Totp\Exceptions\SecureRandomDataUnavailableException if Totp::randomSecret() is unable to provide
     * cryptographically-secure random data.
     */
    public function testRandomSecret1(): void
    {
        for ($idx = 0; $idx < 100; ++$idx) {
            self::assertGreaterThanOrEqual(64, strlen(Factory::randomSecret()->raw()), "randomSecret() did not return a sufficiently large byte sequence.");
        }
    }

    /** Ensure we fall back on openssl when random_bytes can't give us a random secret. */
    public function testRandomSecret2(): void
    {
        Mokkd::func("random_bytes")
            ->expects(64)
            ->once()
            ->throwing(new Exception("Test exception from random_bytes()"));

        Mokkd::func("openssl_random_pseudo_bytes")
            ->expects(64, new Mokkd\Matchers\Any())
            ->once()
            ->returningUsing(static function (int $bytes, mixed &$isStrong): string {
                $isStrong = true;
                return "a-super-un-strong-random-secret-from-openssl_random_pseudo_bytes";
            });

        // we still get this exception as presently there's no way of mocking by-reference parameters so $isStrong is
        // always false. Mokkd ensures the call is made
        $this->expectException(SecureRandomDataUnavailableException::class);
        $this->expectExceptionMessage("Test exception from random_bytes()");
        Factory::randomSecret();
    }

    /** Ensure we throw when random_bytes() can't provide data and openssl_random_pseudo_bytes() isn't available. */
    public function testRandomSecret3(): void
    {
        Mokkd::func("random_bytes")
            ->expects(64)
            ->once()
            ->throwing(new Exception("Test exception from random_bytes()"));

        Mokkd::func("function_exists")
            ->expects("openssl_random_pseudo_bytes")
            ->once()
            ->returning(false);

        $this->expectException(SecureRandomDataUnavailableException::class);
        $this->expectExceptionMessage("Test exception from random_bytes()");
        Factory::randomSecret();
    }

    /**
     * Ensure we throw when random_bytes() can't provide data and openssl_random_pseudo_bytes() can't provide strong
     * randomness.
     */
    public function testRandomSecret4(): void
    {
        Mokkd::func("random_bytes")
            ->expects(64)
            ->once()
            ->throwing(new Exception("Test exception from random_bytes()"));

        Mokkd::func("openssl_random_pseudo_bytes")
            ->expects(64, new Mokkd\Matchers\Any())
            ->once()
            ->returningUsing(static function (int $bytes, mixed &$isStrong): string {
                $isStrong = false;
                return "a-super-un-strong-random-secret-from-openssl_random_pseudo_bytes";
            });

        $this->expectException(SecureRandomDataUnavailableException::class);
        $this->expectExceptionMessage("Test exception from random_bytes()");
        Factory::randomSecret();
    }
}
