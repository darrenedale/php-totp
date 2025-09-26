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

namespace Equit\TotpTests;

use DateTime;
use DateTimeZone;
use Equit\Totp\Contracts\IntegerRenderer;
use Equit\Totp\Contracts\Renderer;
use Equit\Totp\Exceptions\InvalidHashAlgorithmException;
use Equit\Totp\Exceptions\InvalidSecretException;
use Equit\Totp\Exceptions\InvalidTimeException;
use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\Totp\Exceptions\InvalidVerificationWindowException;
use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Renderers\SixDigits;
use Equit\Totp\Totp;
use Equit\Totp\Types\Digits;
use Equit\Totp\Types\HashAlgorithm;
use Equit\TotpTests\Framework\TestCase;
use Equit\Totp\Factory;
use Equit\Totp\Types\Secret;
use Equit\Totp\Types\TimeStep;
use Equit\XRay\XRay;
use Generator;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionException;
use ReflectionMethod;
use ReflectionProperty;
use TypeError;

/**
 * Unit test for the Totp class.
 *
 * The only code in the test subject that is not covered is the case where randomSecret() can't provide a secret because
 * random_bytes() is unable to provide cryptographically-secure data, and we can't mock that scenario as far as I can
 * tell.
 */
class TotpTest extends TestCase
{
    /**
     * Just a random secret to use to initialise a Totp instance for testing.
     */
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
     * The full test data for the test cases outlined in RFC 6238 (page 15).
     *
     * Note that in most versions of the RFC available online the SHA256 and SHA512 passwords appear to be incorrect.
     * The password values in the data below have been externally verified using oathtool
     * (https://www.nongnu.org/oath-toolkit/).
     *
     * @return array[]
     * @noinspection PhpDocMissingThrowsInspection The DateTime constructor will not throw in these cases.
     */
    protected static function rfcTestData(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection The DateTime constructor will not throw in these cases. */
        return [
            "rfcTestData-sha1-59" => [
                "algorithm" => "sha1",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 59,
                "time" => new DateTime("1970-01-01 00:00:59", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x00\x00\x00\x01",
                "hmac" => "\x75\xa4\x8a\x19\xd4\xcb\xe1\x00\x64\x4e\x8a\xc1\x39\x7e\xea\x74\x7a\x2d\x33\xab",
                "passwords" => [
                    "8" => "94287082",
                    "7" => "4287082",
                    "6" => "287082",
                ],
            ],
            "rfcTestData-sha1-1111111109" => [
                "algorithm" => "sha1",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1111111109,
                "time" => new DateTime("2005-03-18 01:58:29", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xEC",
                "hmac" => "\x27\x8c\x02\xe5\x36\x10\xf8\x4c\x40\xbd\x91\x35\xac\xd4\x10\x10\x12\x41\x0a\x14",
                "passwords" => [
                    "8" => "07081804",
                    "7" => "7081804",
                    "6" => "081804",
                ],
            ],
            "rfcTestData-sha1-1111111111" => [
                "algorithm" => "sha1",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1111111111,
                "time" => new DateTime("2005-03-18 01:58:31", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xED",
                "hmac" => "\xb0\x09\x2b\x21\xd0\x48\xaf\x20\x9d\xa0\xa1\xdd\xd4\x98\xad\xe8\xa7\x94\x87\xed",
                "passwords" => [
                    "8" => "14050471",
                    "7" => "4050471",
                    "6" => "050471",
                ],
            ],
            "rfcTestData-sha1-1234567890" => [
                "algorithm" => "sha1",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1234567890,
                "time" => new DateTime("2009-02-13 23:31:30", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x73\xEF\x07",
                "hmac" => "\x90\x7c\xd1\xa9\x11\x65\x64\xec\xb9\xd5\xd1\x78\x03\x25\xf2\x46\x17\x3f\xe7\x03",
                "passwords" => [
                    "8" => "89005924",
                    "7" => "9005924",
                    "6" => "005924",
                ],
            ],
            "rfcTestData-sha1-2000000000" => [
                "algorithm" => "sha1",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 2000000000,
                "time" => new DateTime("2033-05-18 03:33:20", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x03\xF9\x40\xAA",
                "hmac" => "\x25\xa3\x26\xd3\x1f\xc3\x66\x24\x4c\xad\x05\x49\x76\x02\x0c\x7b\x56\xb1\x3d\x5f",
                "passwords" => [
                    "8" => "69279037",
                    "7" => "9279037",
                    "6" => "279037",
                ],
            ],
            "rfcTestData-sha1-20000000000" => [
                "algorithm" => "sha1",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 20000000000,
                "time" => new DateTime("2603-10-11 11:33:20", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x27\xBC\x86\xAA",
                "hmac" => "\xab\x07\xe9\x7e\x2c\x12\x78\x76\x9d\xbc\xd7\x57\x83\xaa\xbd\xe7\x5e\xd8\x55\x0a",
                "passwords" => [
                    "8" => "65353130",
                    "7" => "5353130",
                    "6" => "353130",
                ],
            ],
            "rfcTestData-sha256-59" => [
                "algorithm" => "sha256",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 59,
                "time" => new DateTime("1970-01-01 00:00:59", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x00\x00\x00\x01",
                "hmac" => "\xec\x9d\x4f\x68\x7b\x4e\xfe\x6a\xcc\x52\x10\x06\x72\x66\x0b\x84\xc0\xe7\x21\x0b\xa0\x38\x21\x41\xf8\xec\xb9\x07\x96\xca\xb9\x12",
                "passwords" => [
                    "8" => "32247374",
                    "7" => "2247374",
                    "6" => "247374",
                ],
            ],
            "rfcTestData-sha256-1111111109" => [
                "algorithm" => "sha256",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1111111109,
                "time" => new DateTime("2005-03-18 01:58:29", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xEC",
                "hmac" => "\x89\x89\x00\x43\x35\xf6\x3d\xe5\x06\x88\x08\x38\x17\xcc\xa9\xc0\xd2\xdb\x3f\x96\x0b\x7e\x2a\x6a\x42\xbf\x43\x93\x09\xb3\x20\x69",
                "passwords" => [
                    "8" => "34756375",
                    "7" => "4756375",
                    "6" => "756375",
                ],
            ],
            "rfcTestData-sha256-1111111111" => [
                "algorithm" => "sha256",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1111111111,
                "time" => new DateTime("2005-03-18 01:58:31", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xED",
                "hmac" => "\x38\x21\xe8\x09\x89\x0a\x4c\xb7\x4a\x18\xfa\x46\x11\x01\xcd\xb4\x21\x19\x6e\xe0\xb6\x98\x17\xc3\x22\x20\xa5\x46\xe3\x27\x64\x7f",
                "passwords" => [
                    "8" => "74584430",
                    "7" => "4584430",
                    "6" => "584430",
                ],
            ],
            "rfcTestData-sha256-1234567890" => [
                "algorithm" => "sha256",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1234567890,
                "time" => new DateTime("2009-02-13 23:31:30", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x73\xEF\x07",
                "hmac" => "\x6a\xc3\x5a\xfc\x61\xeb\x98\x02\x05\xcc\x2b\x9f\xea\x97\x98\xd0\x79\xe2\xa9\x15\xfc\xf7\xcf\xb4\xd0\x3a\x14\xba\x7a\xf1\x84\xf4",
                "passwords" => [
                    "8" => "42829826",
                    "7" => "2829826",
                    "6" => "829826",
                ],
            ],
            "rfcTestData-sha256-2000000000" => [
                "algorithm" => "sha256",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 2000000000,
                "time" => new DateTime("2033-05-18 03:33:20", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x03\xF9\x40\xAA",
                "hmac" => "\xc3\x09\x31\x64\x31\x1c\x84\x3e\x15\x5f\x9b\x0d\xc6\x8e\x7d\x2c\x75\xa8\x51\xdc\x05\x29\xa8\x0b\xbf\xe6\x7a\x76\xe8\xd9\x65\x45",
                "passwords" => [
                    "8" => "78428693",
                    "7" => "8428693",
                    "6" => "428693",
                ],
            ],
            "rfcTestData-sha256-20000000000" => [
                "algorithm" => "sha256",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 20000000000,
                "time" => new DateTime("2603-10-11 11:33:20", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x27\xBC\x86\xAA",
                "hmac" => "\x17\xca\x1f\x3d\xc7\x4a\x9b\x14\x51\x06\x03\x82\x25\x08\x94\x76\x69\x35\x1a\xdc\xe9\xe1\x54\xd0\x02\xa1\x09\xbc\xaf\x6e\x10\x72",
                "passwords" => [
                    "8" => "24142410",
                    "7" => "4142410",
                    "6" => "142410",
                ],
            ],
            "rfcTestData-sha512-59" => [
                "algorithm" => "sha512",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 59,
                "time" => new DateTime("1970-01-01 00:00:59", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x00\x00\x00\x01",
                "hmac" => "\x68\xa0\xd9\xfc\x7f\x6b\xc8\xe3\x06\x0a\x4c\xa7\x99\x96\x03\xb6\xc3\x5d\x4a\xf7\xb2\x9e\x18\xc5\x4f\x4f\x91\x8c\x24\x40\xb4\x7b\x6d\x8e\x2b\x2b\x46\xdf\x25\xf1\x24\x30\x68\xa9\x26\x2d\x81\xc8\x87\x9e\x07\xd5\x49\x91\xa5\xec\x78\x3d\xb7\x38\x4b\x0b\x91\x0d",
                "passwords" => [
                    "8" => "69342147",
                    "7" => "9342147",
                    "6" => "342147",
                ],
            ],
            "rfcTestData-sha512-1111111109" => [
                "algorithm" => "sha512",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1111111109,
                "time" => new DateTime("2005-03-18 01:58:29", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xEC",
                "hmac" => "\xc2\xde\x99\x12\x47\xda\x69\x15\xff\x7a\x2e\xe3\x21\xbd\xf9\xfa\x08\x46\x4c\xde\xe5\x28\x67\xd0\x1c\x4b\xeb\xf0\x0f\x3d\xa0\xc4\x22\xd5\x6a\xe1\x18\x50\xa1\xf7\xc9\xb5\xda\xe5\x23\xa2\x34\xb3\xea\xf9\x4f\xcc\xa4\x4d\xdf\x95\xdb\x1b\x0c\x28\xb9\x3b\xf1\x36",
                "passwords" => [
                    "8" => "63049338",
                    "7" => "3049338",
                    "6" => "049338",
                ],
            ],
            "rfcTestData-sha512-1111111111" => [
                "algorithm" => "sha512",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1111111111,
                "time" => new DateTime("2005-03-18 01:58:31", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x35\x23\xED",
                "hmac" => "\x0c\x42\xa6\x91\xcd\x7d\xa3\x88\x09\x75\x15\x1f\x69\x5a\xf8\x06\xc3\x23\xf3\xba\xda\x29\x6d\x00\x0d\x80\x3a\x85\x3b\xee\xfc\x77\x2f\xbb\x28\x4f\xe0\x2d\xcd\x74\xca\xb7\x07\x57\xc5\xfe\x62\x7a\x6e\x3d\xa5\x44\x2e\xdb\xb2\x56\x8a\x99\xc5\xa5\xbb\x4e\x63\xaa",
                "passwords" => [
                    "8" => "54380122",
                    "7" => "4380122",
                    "6" => "380122",
                ],
            ],
            "rfcTestData-sha512-1234567890" => [
                "algorithm" => "sha512",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 1234567890,
                "time" => new DateTime("2009-02-13 23:31:30", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x02\x73\xEF\x07",
                "hmac" => "\x1e\xf4\x91\x8d\x06\xb1\xd6\xb8\x1b\xcc\x18\x76\x5a\xe4\x17\x72\x34\x5f\xc4\x8a\xb5\x1e\xe4\xb0\x67\x7f\x60\x8d\x0d\x94\xcd\xd8\x12\xdf\xc3\x96\xda\x54\x93\x38\xef\x93\xca\x2d\xde\x40\x94\xaf\x85\xa9\x93\xe8\x84\xbc\xf9\xa2\x3a\xbc\x42\x9b\x68\x32\x0b\x89",
                "passwords" => [
                    "8" => "76671578",
                    "7" => "6671578",
                    "6" => "671578",
                ],
            ],
            "rfcTestData-sha512-2000000000" => [
                "algorithm" => "sha512",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 2000000000,
                "time" => new DateTime("2033-05-18 03:33:20", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x03\xF9\x40\xAA",
                "hmac" => "\x86\x28\x9f\x44\x00\x4e\x5d\x4c\x3f\xfd\x20\xcd\x56\xcf\xe2\x94\x7f\x8a\xf2\xfc\xbc\x03\xc6\xf6\xa5\xa2\x6f\x79\xec\xb8\xbb\x8b\x05\x74\xa4\x5f\x19\x87\x31\x1d\x71\x30\x43\x0d\xdc\x4d\x1d\x65\xfe\x7a\xea\x62\xf3\xca\xcf\x6d\x42\x27\x89\x0e\xe2\xdd\x5f\x3c",
                "passwords" => [
                    "8" => "56464532",
                    "7" => "6464532",
                    "6" => "464532",
                ],
            ],
            "rfcTestData-sha512-20000000000" => [
                "algorithm" => "sha512",
                "referenceTimestamp" => 0,
                "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
                "time-step" => 30,
                "timestamp" => 20000000000,
                "time" => new DateTime("2603-10-11 11:33:20", new DateTimeZone("UTC")),
                "secret" => [
                    "raw" => "12345678901234567890",
                    "base32" => "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "base64" => "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
                ],
                "counterBytes" => "\x00\x00\x00\x00\x27\xBC\x86\xAA",
                "hmac" => "\xdb\x6c\x6c\xf2\x0e\x72\x9a\x82\xdb\xa6\xe2\x7b\x22\x43\x3f\xbf\x00\x0a\x8a\xae\x2b\x6f\x20\x35\xec\xaf\x84\xcb\xe1\x75\x01\xf9\x83\x54\xb3\x44\xe8\x27\x68\x0b\x2f\x46\xe1\xf7\x1b\xd2\xfc\x9b\x11\x89\xd8\x2a\xcc\xa2\x2b\x87\x75\x37\xfa\x66\x2f\x4c\x2a\x2e",
                "passwords" => [
                    "8" => "69481994",
                    "7" => "9481994",
                    "6" => "481994",
                ],
            ],
        ];
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

    /**
     * Test data for testDestructor().
     *
     * @return \Generator
     * @throws \Exception if self::randomValidSecret() is unable to generate cryptographically-secure random data.
     */
    public static function dataForTestDestructor(): Generator
    {
        yield "typicalAsciiSecret" => ["password-password"];
        yield "nullBytes16Secret" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"];
        yield "nullBytes20Secret" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"];

        // yield 100 random valid secrets
        for ($idx = 0; $idx < 100; ++$idx) {
            yield [self::randomValidSecret(),];
        }
    }

    /**
     * Test the Totp destructor.
     *
     * @dataProvider dataForTestDestructor
     *
     * @param string $secret The secret to use to initialise the Totp object.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor won't throw, secret is guaranteed by the data
     * provider to be valid. ReflectionProperty won't throw because we know the property exists.
     */
    public function testDestructor(string $secret): void
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        $totp = (new Factory())->totp(Secret::fromRaw($secret));

        $totp->__destruct();
        self::assertAllCharactersHaveChanged($secret, (new XRay($totp))->secret, "The secret was not overwritten with random data.");
    }

//
//    /**
//     * Data provider for testSetBase32Secret().
//     *
//     * @return array The test data.
//     */
//    public static function dataForTestSetBase32Secret(): array
//    {
//        return [
//            "typicalPlainText" => ["OBQXG43XN5ZGILLQMFZXG53POJSA====", "password-password",],
//            "typicalBinary" => ["CVYNPLS6RDRTYW2JY6U46JPTD7N2Z645", "\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d",],
//            "invalidEmpty" => ["", null, InvalidSecretException::class,],
//            "invalidTooShort" => ["OBQXG43XN5ZGI===", null, InvalidSecretException::class,],
//            "invalidWrongTypeNull" => [null, null, TypeError::class,],
//            "invalidWrongTypeStringable" => [self::createStringable("OBQXG43XN5ZGILLQMFZXG53POJSA===="), null, TypeError::class,],
//        ];
//    }
//
//    /**
//     * @dataProvider dataForTestSetBase32Secret
//     *
//     * @param mixed $base32 The base32-encoded secret to set.
//     * @param string|null $raw The raw secret expected.
//     * @param string|null $exceptionClass The class name of the exception expected to be thrown, if any.
//     *
//     * @noinspection PhpDocMissingThrowsInspection Totp::setSecret() should only throw expected test exceptions.
//     * TotpSecret::fromBase32() shouldn't throw with test data.
//     */
//    public function testSetBase32Secret(mixed $base32, string|null $raw, ?string $exceptionClass = null): void
//    {
//        if (isset($exceptionClass)) {
//            $this->expectException($exceptionClass);
//        }
//
//        $totp = self::createFactory();
//
//        /** @noinspection PhpUnhandledExceptionInspection setSecret() should only throw expected test exceptions.
//         * fromBase32() shouldn't throw with test data.
//         */
//        $totp->setSecret(Secret::fromBase32($base32));
//        self::assertSame($base32, $totp->base32Secret());
//
//        if (isset($raw)) {
//            self::assertSame($raw, $totp->secret());
//        }
//    }
//
//    /**
//     * Data provider for testSetBase32Secret().
//     *
//     * @return array The test data.
//     */
//    public static function dataForTestSetBase64Secret(): array
//    {
//        return [
//            "typicalPlainText" => ["cGFzc3dvcmQtcGFzc3dvcmQ=", "password-password",],
//            "typicalBinary" => ["FXDXrl6I4zxbScepzyXzH9us+50=", "\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d",],
//            "invalidEmpty" => ["", null, InvalidSecretException::class,],
//            "invalidTooShort" => ["cGFzc3dvcmQ=", null, InvalidSecretException::class,],
//            "invalidWrongTypeNull" => [null, null, TypeError::class,],
//            "invalidWrongTypeStringable" => [self::createStringable("cGFzc3dvcmQtcGFzc3dvcmQ="), null, TypeError::class,],
//        ];
//    }
//
//    /**
//     * @dataProvider dataForTestSetBase64Secret
//     *
//     * @param mixed $base64 The base64-encoded secret to set.
//     * @param string|null $raw The raw secret expected.
//     * @param string|null $exceptionClass The class name of the exception expected to be thrown, if any.
//     *
//     * @noinspection PhpDocMissingThrowsInspection Totp::setSecret() should only throw expected test exceptions.
//     * TotpSecret::fromBase64() shouldn't throw with test data.
//     */
//    public function testSetBase64Secret(mixed $base64, string|null $raw, ?string $exceptionClass = null): void
//    {
//        if (isset($exceptionClass)) {
//            $this->expectException($exceptionClass);
//        }
//
//        $totp = self::createFactory();
//
//        /** @noinspection PhpUnhandledExceptionInspection setSecret() should only throw expected test exceptions.
//         * fromBase64() shouldn't throw with test data.
//         */
//        $totp->setSecret(Secret::fromBase64($base64));
//        self::assertSame($base64, $totp->base64Secret());
//
//        if (isset($raw)) {
//            self::assertSame($raw, $totp->secret());
//        }
//    }
//
//    /**
//     * Test data for testBase64Secret().
//     *
//     * @return array The test data.
//     */
//    public static function dataForTestBase64Secret(): array
//    {
//        return [
//            "typicalPlainText" => ["password-password", "cGFzc3dvcmQtcGFzc3dvcmQ=",],
//            "typicalBinary" => ["\x15\x70\xd7\xae\x5e\x88\xe3\x3c\x5b\x49\xc7\xa9\xcf\x25\xf3\x1f\xdb\xac\xfb\x9d", "FXDXrl6I4zxbScepzyXzH9us+50=",],
//            "extremeBinaryZeroes" => ["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",],
//            "extremeBinaryOnes" => ["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "//////////////////////////8=",],
//            "extremeLongBinary" => [
//                "\x4d\x51\xa7\x96\x6f\x8f\xf6\xcb\x19\xb5\x61\x2f\xe8\x77\xa8\x78\x26\xb7\xcc\x92\x09\xa0\xe0\x6c\x1a\x8e\x99\x30\x61\x1c\xfc\x18\xd4\x9e\xae\x78\x0c\xc0\x5e\x73\x0c\xd5\x55\x25\x5b\x39\x2a\xd9\x64\x95\xf5\x36\xa5\xe8\x64\x06\xf0\x73\x58\xfc\xfa\x27\xd5\x15\xe5\xa9\x62\xce\x0c\x04\x1e\xa6\xbd\xbc\xde\x61\xb5\x95\xca\x42\x94\xb5\x1b\x1e\xe3\x8c\xde\x14\xb2\x8a\x00\x10\xd4\x96\xa8\xd0\x33\xf6\x7e\x85\xc4\x3e\x94\x5c\xe2\xe5\x6a\x24\x5a\x5e\x27\x2c\xd0\xed\xb0\x33\xe4\x4e\x1a\xcc",
//                "TVGnlm+P9ssZtWEv6HeoeCa3zJIJoOBsGo6ZMGEc/BjUnq54DMBecwzVVSVbOSrZZJX1NqXoZAbwc1j8+ifVFeWpYs4MBB6mvbzeYbWVykKUtRse44zeFLKKABDUlqjQM/Z+hcQ+lFzi5WokWl4nLNDtsDPkThrM",
//            ],
//        ];
//    }
//
//    /**
//     * @dataProvider dataForTestBase64Secret
//     *
//     * @param string $raw The raw secret.
//     * @param string $base64 The expected Base64 for the raw secret.
//     *
//     * @noinspection PhpDocMissingThrowsInspection Totp::setSecret() shouldn't throw with test data.
//     */
//    public function testBase64Secret(string $raw, string $base64): void
//    {
//        $totp = self::createFactory();
//        /** @noinspection PhpUnhandledExceptionInspection setSecret() shouldn't throw with test data. */
//        $totp->setSecret($raw);
//        self::assertSame($base64, $totp->base64Secret(), "The base64 of the raw secret '" . self::hexOf($raw) . "' did not match the expected string.");
//    }

    /**
     * Data provider for testHashAlgorithm().
     *
     * @return array The test data.
     */
    public static function dataForTestHashAlgorithm(): array
    {
        return [
            "typicalSha1" => [HashAlgorithm::Sha1Algorithm,],
            "typicalSha256" => [HashAlgorithm::Sha256Algorithm,],
            "typicalSha512" => [HashAlgorithm::Sha512Algorithm,],
        ];
    }

    /**
     * Test the hashAlgorithm() method.
     *
     * Note that each run of this test asserts that the default algorithm is SHA1.
     *
     * @dataProvider dataForTestHashAlgorithm
     *
     * @param string $algorithm The algorithm to test with.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::setHashAlgorithm() shouldn't throw with test data.
     */
    public function testHashAlgorithm(string $algorithm): void
    {
        $totp = self::createTotp(hashAlgorithm: $algorithm);
        self::assertSame($algorithm, $totp->hashAlgorithm()->algorithm(), "The hash algorithm was expected to be {$algorithm} but {$totp->hashAlgorithm()->algorithm()} was reported.");
    }

    /**
     * Date provider for dataForTestReferenceTimestamp().
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public static function dataForTestReferenceTimestamp(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        return [
            "epoch" => [0,],
            "epochAsDateTime" => [new DateTime("@0"), 0,],
            "epochAsDateTimeUtc+4" => [new DateTime("@0", new DateTimeZone("UTC")), 0,],
            "nowAsTimestamp" => [time(),],
            "10YearsAgoAsTimestamp" => [time() - self::yearsInSeconds(10),],
            "10DaysAgoAsTimestamp" => [time() - self::daysInSeconds(10),],
            "10YearsAfterEpoch" => [self::yearsInSeconds(10),],
            "20YearsAfterEpoch" => [self::yearsInSeconds(20),],
            "30YearsAfterEpoch" => [self::yearsInSeconds(30),],
            "10SecondsAfterEpoch" => [self::daysInSeconds(10),],
            "20SecondsAfterEpoch" => [self::daysInSeconds(20),],
            "30SecondsAfterEpoch" => [self::daysInSeconds(30),],
            "40SecondsAfterEpoch" => [self::daysInSeconds(40),],
            "50SecondsAfterEpoch" => [self::daysInSeconds(50),],
            "60SecondsAfterEpoch" => [self::daysInSeconds(60),],
            "70SecondsAfterEpoch" => [self::daysInSeconds(70),],
            "80SecondsAfterEpoch" => [self::daysInSeconds(80),],
            "90SecondsAfterEpoch" => [self::daysInSeconds(90),],
            "100SecondsAfterEpoch" => [self::daysInSeconds(100),],
            "nowAsDateTime" => [new DateTime("@" . time()), time(),],
            "dateTimeUtc" => [new DateTime("23-04-1974", new DateTimeZone("UTC")), 135907200,],
            "dateTimeUtc-4" => [new DateTime("28-01-1978", new DateTimeZone("-0400")), 254808000,],
            "dateTimeUtc+4" => [new DateTime("19-07-2000", new DateTimeZone("+0400")), 963950400,],
            "dateTimeUtc-6" => [new DateTime("04-03-1984", new DateTimeZone("-0600")), 447228000,],
            "dateTimeUtc+6" => [new DateTime("31-12-1999", new DateTimeZone("+0600")), 946576800,],
        ];
    }

    /**
     * @dataProvider dataForTestReferenceTimestamp
     *
     * @param int|\DateTime $time The time to set in the Totp as the reference.
     * @param int|null $expectedTimestamp What referenceTimestamp() is expected to return.
     */
    public function testReferenceTimestamp(int|DateTime $time, ?int $expectedTimestamp = null): void
    {
        if (!isset($expectedTimestamp)) {
            if (!is_int($time)) {
                throw new InvalidArgumentException("Test data for testReferenceTimestamp expects \$time to be an int if \$expectedTimestamp is not specified.");
            }

            $expectedTimestamp = $time;
        }

        $totp = self::createTotp(referenceTime: $time);
        self::assertSame($expectedTimestamp, $totp->referenceTimestamp());
    }

    /**
     * Date provider for testReferenceTime().
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public static function dataForTestReferenceTime(): array
    {
        $now = time();

        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        return [
            "epoch" => [0, new DateTime("@0")],
            "epochAsDateTime" => [new DateTime("@0"),],
            "epochAsDateTimeUtc+4" => [new DateTime("@0", new DateTimeZone("UTC")),],
            "nowAsTimestamp" => [$now, new DateTime("@{$now}")],
            "10YearsAgoAsTimestamp" => [$now - self::yearsInSeconds(10), new DateTime("@" . ($now - self::yearsInSeconds(10))),],
            "10DaysAgoAsTimestamp" => [$now - self::daysInSeconds(10), new DateTime("@" . ($now - self::daysInSeconds(10))),],
            "10YearsAfterEpoch" => [self::yearsInSeconds(10), new DateTime("@" . self::yearsInSeconds(10)),],
            "20YearsAfterEpoch" => [self::yearsInSeconds(20), new DateTime("@" . self::yearsInSeconds(20)),],
            "30YearsAfterEpoch" => [self::yearsInSeconds(30), new DateTime("@" . self::yearsInSeconds(30)),],
            "10SecondsAfterEpoch" => [self::daysInSeconds(10), new DateTime("@" . self::daysInSeconds(10)),],
            "20SecondsAfterEpoch" => [self::daysInSeconds(20), new DateTime("@" . self::daysInSeconds(20)),],
            "30SecondsAfterEpoch" => [self::daysInSeconds(30), new DateTime("@" . self::daysInSeconds(30)),],
            "40SecondsAfterEpoch" => [self::daysInSeconds(40), new DateTime("@" . self::daysInSeconds(40)),],
            "50SecondsAfterEpoch" => [self::daysInSeconds(50), new DateTime("@" . self::daysInSeconds(50)),],
            "60SecondsAfterEpoch" => [self::daysInSeconds(60), new DateTime("@" . self::daysInSeconds(60)),],
            "70SecondsAfterEpoch" => [self::daysInSeconds(70), new DateTime("@" . self::daysInSeconds(70)),],
            "80SecondsAfterEpoch" => [self::daysInSeconds(80), new DateTime("@" . self::daysInSeconds(80)),],
            "90SecondsAfterEpoch" => [self::daysInSeconds(90), new DateTime("@" . self::daysInSeconds(90)),],
            "100SecondsAfterEpoch" => [self::daysInSeconds(100), new DateTime("@" . self::daysInSeconds(100)),],
            "nowAsDateTime" => [new DateTime("@{$now}"),],
            "dateTimeUtc" => [new DateTime("23-04-1974", new DateTimeZone("UTC")),],
            "dateTimeUtc-4" => [new DateTime("28-01-1978", new DateTimeZone("-0400")),],
            "dateTimeUtc+4" => [new DateTime("19-07-2000", new DateTimeZone("+0400")),],
            "dateTimeUtc-6" => [new DateTime("04-03-1984", new DateTimeZone("-0600")),],
            "dateTimeUtc+6" => [new DateTime("31-12-1999", new DateTimeZone("+0600")),],
        ];
    }

    /**
     * @dataProvider dataForTestReferenceTime
     *
     * @param int|\DateTime $time The time to set in the Totp as the reference.
     * @param DateTime|null $expectedDateTime What referenceTime() is expected to return.
     */
    public function testReferenceTime(int|DateTime $time, ?DateTime $expectedDateTime = null): void
    {
        if (!isset($expectedDateTime)) {
            if (!($time instanceof DateTime)) {
                throw new InvalidArgumentException("Test data for testReferenceTimestamp expects \$time to be a DateTime instance if \$expectedDateTime is not specified.");
            }

            $expectedDateTime = $time;
        }

        $totp = self::createTotp(referenceTime: $time);
        self::assertEquals($expectedDateTime, $totp->referenceTime());
    }

    /**
     * Data provider for testTimeStep()
     *
     * @return Generator The test data.
     */
    public static function dataForTestTimeStep(): Generator
    {
        // test with all valid time steps up to 1 hour
        for ($timeStep = 1; $timeStep <= 3600; ++$timeStep) {
            yield [$timeStep,];
        }
    }

    /**
     * Test the timeStep() method.
     *
     * @dataProvider dataForTestTimeStep
     *
     * @param int $timeStep The timeStep to test with.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::setTimeStep() shouldn't throw with test data.
     */
    public function testTimeStep(int $timeStep): void
    {
        $totp = self::createTotp(timeStep: $timeStep);
        self::assertSame($timeStep, $totp->timeStep()->seconds(), "The time step {$timeStep} was expected but {$totp->timeStep()} was reported.");
    }

    /**
     * Test data for testSecret.
     *
     * @return \Generator
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function dataForTestSecret(): iterable
    {
        // 100 datasets with random valid secrets
        for ($idx = 0; $idx < 100; ++$idx) {
            yield "secret" . sprintf("%02d", $idx) => [self::randomValidSecret(),];
        }
    }

    /**
     * @dataProvider dataForTestSecret
     *
     * @param string $secret
     *
     * @noinspection PhpDocMissingThrowsInspection setSecret() shouldn't throw with test data.
     */
    public function testSecret(string $secret): void
    {
        $totp = self::createTotp($secret);
        self::assertSame($secret, $totp->secret(), "The secret returned from Totp::secret() is not as expected.");
    }


    /**
     * Test data for testSetRenderer()
     *
     * @return array
     * @noinspection PhpDocMissingThrowsInspection Integer renderer constructor shouldn't throw with test data.
     */
    public static function dataForTestRenderer(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection Integer renderer constructor shouldn't throw with test data. */
        return [
            "sixDigits" => [new SixDigits(),],
            "eightDigits" => [new EightDigits(),],
            "integer6Digits" => [new Integer(new Digits(6)),],
            "integer7Digits" => [new Integer(new Digits(7)),],
            "integer8Digits" => [new Integer(new Digits(8)),],
            "integer9Digits" => [new Integer(new Digits(9)),],
            "integer10Digits" => [new Integer(new Digits(10)),],
            "anonymousClass" => [new class implements Renderer
            {
                public function name(): string
                {
                    return "insecure renderer";
                }

                public function render(string $hmac): string
                {
                    return "insecure";
                }
            },],
        ];
    }

    /**
     * @dataProvider dataForTestRenderer
     *
     * @param \Equit\Totp\Contracts\Renderer $renderer
     */
    public function testRenderer(Renderer $renderer): void
    {
        $totp = self::createTotp(renderer: $renderer);
        self::assertEquals($renderer, $totp->renderer(), "Unexpected object returned from renderer() method.");
    }

    /**
     * Test data for testCounterAt().
     *
     * Each dataset consists of the current time at which the counter should be checked and the expected value for the
     * counter. In all cases, the TOTP has its reference date set to the Unix epoch and a time step of 30 seconds.
     *
     * @return \int[][]
     */
    public static function dataForTestCounterAt(): array
    {
        return [
            // test data from RFC 6238
            [59, 1,],
            [1111111109, 37037036,],
            [1111111111, 37037037,],
            [1234567890, 41152263,],
            [2000000000, 66666666,],
            [20000000000, 666666666,],

            // test data for non-default reference time
            [119, 1, 60,],
            [121, 2, 60,],

            // test data for non-default time step
            [59, 5, null, 10,],
            [61, 6, null, 10,],

            // test data for non-default time step and non-default reference time
            [119, 5, 60, 10,],
            [121, 6, 60, 10,],

            // test for invalid time
            [60, 0, 120, 30, InvalidTimeException::class,],
        ];
    }

    /**
     * @dataProvider dataForTestCounterAt
     *
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
    public function testCounterAt(int|DateTime $currentTime, int $expectedCounter, int|DateTime|null $referenceTime = null, ?int $timeStep = null, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $totp = self::createTotp(referenceTime: $referenceTime ?? 0, timeStep: $timeStep ?? 30);

        /** @noinspection PhpUnhandledExceptionInspection counterAt() should only throw expected test exceptions. */
        $actualCounter = $totp->counterAt($currentTime);
        self::assertSame($expectedCounter, $actualCounter, "The counter is expected to be {$expectedCounter} but is actually {$actualCounter}.");
    }

    /**
     * Test data for the counterBytes() method.
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor should not throw with test data.
     */
    public static function dataForTestCounter(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor should not throw with test data. */
        return [
            "sha1-6digit-1970" => [],
            "sha256-6digit-1970" => [null, HashAlgorithm::Sha256Algorithm,],
            "sha512-6digit-1970" => [null, HashAlgorithm::Sha512Algorithm,],
            "sha1-6digit-1974" => [null, HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha256-6digit-1974" => [null, HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha512-6digit-1974" => [null, HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
        ];
    }

    /**
     * @dataProvider dataForTestCounter
     *
     * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor, Totp::counter() and Totp::counterAt() should not
     * throw with test data.
     */
    public function testCounter(?string $secret = null, string $algorithm = HashAlgorithm::Sha1Algorithm, int|DateTime $referenceTime = 0): void
    {
        // The logic behind this test is this: counter() can't return a pre-known value because it produces a value that
        // is dependent on an external factor - the current system time. So we use counterAt() as our source of
        // expectations on the assumption that it provides a correct value. It's safe to do this because we have a test
        // for counterAt() and that test will tell us if it's not working. In order mitigate against the outside chance
        // that the system time ticks over to the next TOTP time step between the point in time at which we call time()
        // and the point in time at which we fetch the actual counter bytes from the Totp object, we ensure that the
        // time after retrieving the bytes from the Totp object is the same as the time we're using as our source of
        // expectation.
        //
        // Note that while debugging, if you put a breakpoint on the call to Totp::counterBytes() you are more likely
        // to trigger a repeat of the loop
        /** @noinspection PhpUnhandledExceptionInspection Totp constructor should not throw with test data. */
        $totp       = self::createTotp(secret: $secret ?? self::TestSecret, referenceTime: $referenceTime, hashAlgorithm: $algorithm);

        // unless you've set a breakpoint we should traverse this loop no more than twice
        do {
            $time = time();
            /** @noinspection PhpUnhandledExceptionInspection counter() should not throw with test data. */
            $actual = $totp->counter();
            /** @noinspection PhpUnhandledExceptionInspection counterAt() should not throw with test data. */
            $expected = $totp->counterAt($time);
            $repeat = (time() !== $time);
        } while ($repeat);

        self::assertSame($expected, $actual, "The generated current counter did not match the expected counter.");
    }

    /**
     * @return array
     */
    public static function dataForTestCounterBytesAt(): array
    {
        return [
            // test data from RFC 6238
            [59, "\x00\x00\x00\x00\x00\x00\x00\x01",],
            [1111111109, "\x00\x00\x00\x00\x02\x35\x23\xEC",],
            [1111111111, "\x00\x00\x00\x00\x02\x35\x23\xED",],
            [1234567890, "\x00\x00\x00\x00\x02\x73\xEF\x07",],
            [2000000000, "\x00\x00\x00\x00\x03\xF9\x40\xAA",],
            [20000000000, "\x00\x00\x00\x00\x27\xBC\x86\xAA",],

            // test data for non-default reference time
            [119, "\x00\x00\x00\x00\x00\x00\x00\x01", 60,],
            [121, "\x00\x00\x00\x00\x00\x00\x00\x02", 60,],

            // test data for non-default time step time
            [59, "\x00\x00\x00\x00\x00\x00\x00\x05", null, 10,],
            [61, "\x00\x00\x00\x00\x00\x00\x00\x06", null, 10,],

            // test data for non-default time step and non-default reference time
            [119, "\x00\x00\x00\x00\x00\x00\x00\x05", 60, 10,],
            [121, "\x00\x00\x00\x00\x00\x00\x00\x06", 60, 10,],
        ];
    }

    /**
     * @dataProvider dataForTestCounterBytesAt
     *
     * @param int|\DateTime $currentTime The time at which to test the bytes.
     * @param string $expectedBytes The expected bytes for the counter. Must be of length 8.
     * @param int|\DateTime|null $referenceTime The reference time for the test TOTP. Default is null: the default for
     * the Totp will be used (the Unix epoch).
     * @param int|null $timeStep The time step for the test TOTP. Default is null: the default for the Totp will be used
     * (30 seconds).
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::setTimeStep() should not throw with test data. ReflectionMethod
     * constructor guaranteed not to throw in this case.
     */
    public function testCounterBytesAt(int|DateTime $currentTime, string $expectedBytes, int|DateTime $referenceTime = null, ?int $timeStep = null): void
    {
        $totp = self::createTotp(
            referenceTime: $referenceTime ?? 0,
            timeStep: $timeStep ?? 30,
        );

        $actualBytes = (new XRay($totp))->counterBytesAt($currentTime);
        self::assertSame($expectedBytes, $actualBytes, "The counter is expected to be " . self::hexOf($expectedBytes) . " but is actually " . self::hexOf($actualBytes) . ".");
    }

    /**
     * Test data for the counterBytes() method.
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public static function dataForTestCounterBytes(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        return [
            "sha1-6digit-1970" => [],
            "sha256-6digit-1970" => [null, HashAlgorithm::Sha256Algorithm,],
            "sha512-6digit-1970" => [null, HashAlgorithm::Sha512Algorithm,],
            "sha1-6digit-1974" => [null, HashAlgorithm::Sha1Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha256-6digit-1974" => [null, HashAlgorithm::Sha256Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
            "sha512-6digit-1974" => [null, HashAlgorithm::Sha512Algorithm, (new DateTime("1974-04-23 00:00:00", new DateTimeZone("UTC"))),],
        ];
    }

    /**
     * @dataProvider dataForTestCounterBytes
     *
     * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor should not throw with test data.
     */
    public function testCounterBytes(string $secret = null, string $algorithm = HashAlgorithm::Sha1Algorithm, int|DateTime $referenceTime = 0): void
    {
        // The logic behind this test is this: counterBytes() can't return a pre-known value because it produces a
        // 64-bit value that is dependent on an external factor - the current system time. So we use counterBytesAt() as
        // our source of expectations on the assumption that it provides a correct value. It's safe to do this because
        // we have a test for counterBytesAt() and that test will tell us if it's not working. In order mitigate against
        // the outside chance that the system time ticks over to the next TOTP time step between the point in time at
        // which we call time() and the point in time at which we fetch the actual counter bytes from the Totp object,
        // we ensure that the time after retrieving the bytes from the Totp object is the same as the time we're using
        // as our source of expectation.
        //
        // Note that while debugging, if you put a breakpoint on the call to Totp::counterBytes() you are more likely
        // to trigger a repeat of the loop
        $totp = self::createTotp(
            secret: $secret ?? self::TestSecret,
            referenceTime: $referenceTime ?? 0,
            hashAlgorithm: $algorithm,
        );

        $xray = new XRay($totp);

        // unless you've set a breakpoint we should traverse this loop no more than twice
        do {
            $time     = time();
            $actual   = $xray->counterBytes();
            $expected = $xray->counterBytesAt($time);
            $repeat   = (time() !== $time);
        } while ($repeat);

        self::assertSame($expected, $actual, "The generated counter bytes did not match the expected counter bytes.");
    }

    /**
     * Test data for the password() method.
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public static function dataForTestHmac(): array
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
     * @dataProvider dataForTestHmac
     *
     * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
     * @param int $digits The number of digits for the password. Defaults to 6.
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor, hmac() and hmacAt() should not throw with
     * test data.
     */
    public function testHmac(string $secret = null, int $digits = 6, string $algorithm = HashAlgorithm::Sha1Algorithm, int|DateTime $referenceTime = 0): void
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
     * @return Generator The test data.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function dataForTestHmacAt(): Generator
    {
        // transform the RFC test data into the args required for testHmacAt()
        yield from array_map(
            function (array $testData) use (&$digits): array {
                return [$testData["secret"]["raw"], 0, $testData["timestamp"], $testData["hmac"], $testData["algorithm"],];
            },
            self::rfcTestData()
        );

        // test for times before TOTP reference time
        yield [self::randomValidSecret(20), 120, 1, "", HashAlgorithm::Sha1Algorithm, InvalidTimeException::class,];
        yield [self::randomValidSecret(32), 120, 1, "", HashAlgorithm::Sha256Algorithm, InvalidTimeException::class,];
        yield [self::randomValidSecret(64), 120, 1, "", HashAlgorithm::Sha512Algorithm, InvalidTimeException::class,];
    }

    /**
     * Test for Totp::hmacAt()
     *
     * @dataProvider dataForTestHmacAt
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
    public function testHmacAt(string $secret, int|DateTime $referenceTime, int|DateTime $currentTime, string $hmac, ?string $algorithm = HashAlgorithm::Sha1Algorithm, ?string $exceptionClass = null): void
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
    public static function dataForTestPassword(): array
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
     * @dataProvider dataForTestPassword
     *
     * @param string|null $secret The TOTP secret. If null, a random secret will be chosen.
     * @param int $digits The number of digits for the password. Defaults to 6.
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor and Integer renderer constructor should not throw
     * with test data. Totp::password() and Totp::passwordAt() should not throw with test data.
     */
    public function testPassword(string $secret = null, int $digits = 6, string $algorithm = HashAlgorithm::Sha1Algorithm, int|DateTime $referenceTime = 0): void
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
     * @return Generator The test data.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function dataForTestPasswordAt(): Generator
    {
        // transform the RFC test data into the args required for testPasswordAt()
        yield from array_map(
            function (array $testData) use (&$digits): array {
                return [$testData["secret"]["raw"], 0, $testData["timestamp"], $testData["passwords"]["8"], $testData["algorithm"],];
            },
            self::rfcTestData()
        );

        // test for times before TOTP reference time
        yield [self::randomValidSecret(20), 120, 1, "", HashAlgorithm::Sha1Algorithm, InvalidTimeException::class,];
        yield [self::randomValidSecret(32), 120, 1, "", HashAlgorithm::Sha256Algorithm, InvalidTimeException::class,];
        yield [self::randomValidSecret(64), 120, 1, "", HashAlgorithm::Sha512Algorithm, InvalidTimeException::class,];
    }

    /**
     * @dataProvider dataForTestPasswordAt
     *
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
    public function testPasswordAt(string $secret, int|DateTime $referenceTime, int|DateTime $currentTime, string $password, ?string $algorithm = HashAlgorithm::Sha1Algorithm, ?string $exceptionClass = null): void
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
     * @return \Generator
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function dataForTestVerify(): Generator
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
     * @dataProvider dataForTestVerify
     *
     * @param string|null $secret The raw bytes of the TOTP secret. If null, a random secret will be chosen.
     * @param int $digits The number of digits for the password. Defaults to 6.
     * @param string $algorithm The hash algorithm to use. Defaults to Totp::Sha1Algorithm.
     * @param int|\DateTime $referenceTime The reference time for the TOTP. Defaults to 0, the Unix epoch.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor, Integer renderer constructor,
     * Totp::password() and Totp::verify() shouldn't throw with test data.
     */
    public function testVerify(string $secret = null, int $digits = 6, string $algorithm = HashAlgorithm::Sha1Algorithm, int|DateTime $referenceTime = 0): void
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
     * @return Generator The test data.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public static function dataForTestVerifyAt(): Generator
    {
        // transforms the RFC data into the structure required for this test
        $extractData = function (array $testData) use (&$digits, &$window): array {
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

        // test the RFC data with windows of 0, 1 and 2 time steps
        $rfcData = self::rfcTestData();

        for ($window = 0; $window < 3; ++$window) {
            for ($digits = 6; $digits <= 8; ++$digits) {
                foreach ($rfcData as $key => $value) {
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
     * @dataProvider dataForTestVerifyAt
     *
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
    public function testVerifyAt(array $totpSpec, int|DateTime $currentTime, int $window, string $userPassword, bool $expectedVerification, string $exceptionClass = null): void
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
