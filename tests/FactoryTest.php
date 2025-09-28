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
use Equit\Totp\Types\Digits;
use Equit\Totp\Types\HashAlgorithm;
use Equit\TotpTests\Framework\TestCase;
use Equit\Totp\Factory;
use Equit\Totp\Types\Secret;
use Equit\Totp\Types\TimeStep;
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
final class FactoryTest extends TestCase
{
    /**
     * Just a random secret to use to initialise a Totp instance for testing.
     */
    protected const TestSecret = "hNDl963Ns6a1gp9d5aZ6";

    /**
     * Helper to create a "vanilla" Totp test instance.
     *
     * @return \Equit\Totp\Factory
     */
    protected static function createFactory(): Factory
    {
        return new Factory();
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
     * Helper to provide some test data for testConstructor.
     *
     * This method yields 100 datasets with random valid time steps then 100 datasets with random invalid time steps.
     *
     * @return \Generator
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    protected function randomTimeStepTestDataForTestConstructor(): iterable
    {
        // 100 x random valid time steps between 1s and 1h
        for ($idx = 0; $idx < 100; ++$idx) {
            $timeStep = new TimeStep(mt_rand(1, 3600));

            yield [
                [null, $timeStep,],
                [
                    "timeStep" => $timeStep,
                ],
            ];
        }
    }

    /**
     * Helper to provide some test data for testConstructor.
     *
     * This method provides test data focused on examining the limits of valid Totp time steps.
     *
     * @return array The test datasets.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    protected function specificTimeStepTestDataForTestConstructor(): array
    {
        return [
            "shortestValidTimeStep" => [
                [null, new TimeStep(1),],
                [
                    "timeStep" => new TimeStep(1),
                ],
            ],
        ];
    }

    /**
     * Helper to provide some test data for testConstructor.
     *
     * Yields 100 datasets each with a valid secret, time step and reference timestamp, then 100 datasets each with a
     * valid secret, time step and reference DateTime.
     *
     * @return \Generator
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    protected function timeStepAndReferenceTimeTestDataForTestConstructor(): iterable
    {
        // 100 x specified secret, time step and reference time as timestamp
        for ($idx = 0; $idx < 100; ++$idx) {
            // random time step up to 1 hour, on a 10-second boundary
            $timeStep           = new TimeStep(10 * mt_rand(1, 360));
            $referenceTimestamp = mt_rand(0, time());

            yield "validSecretTimeStepAndTimestamp" . sprintf("%02d", $idx) => [
                [null, $timeStep, $referenceTimestamp],
                [
                    "timeStep" => $timeStep,
                    "referenceTimestamp" => $referenceTimestamp,
                ],
            ];
        }

        // 100 x specified secret, time step and reference time as DateTime
        for ($idx = 0; $idx < 100; ++$idx) {
            // random time step up to 1 hour, on a 10-second boundary
            $timeStep      = new TimeStep(10 * mt_rand(1, 360));
            $referenceTime = new DateTime("@" . mt_rand(0, time()));

            yield "validSecretTimeStepAndDateTime" . sprintf("%02d", $idx) => [
                [null, $timeStep, $referenceTime],
                [
                    "timeStep" => $timeStep,
                    "referenceTime" => $referenceTime,
                ],
            ];
        }
    }

    /**
     * Helper to provide some test data for testConstructor.
     *
     * Provides datasets to test specific scenarios for the reference time provided to the constructor.
     *
     * @return array
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    protected function specificReferenceTimeTestDataForTestConstructor(): array
    {
        return [
            "nullReferenceTime" => [
                [null, new TimeStep(30), null,],
                [],
                TypeError::class,
            ],
            "stringReferenceTimeNow" => [
                [null, new TimeStep(30), "now",],
                [],
                TypeError::class,
            ],
            "stringReferenceTimeInt" => [
                [null, new TimeStep(30), "0",],
                [],
                TypeError::class,
            ],
            "stringReferenceTimeDateString" => [
                [null, new TimeStep(30), "1970-01-01 00:00:00",],
                [],
                TypeError::class,
            ],
            "objectReferenceTime" => [
                [null, new TimeStep(30), new class
                {
                },],
                [],
                TypeError::class,
            ],
            "arrayReferenceTime" => [
                [null, new TimeStep(30), [0],],
                [],
                TypeError::class,
            ],
        ];
    }

    /**
     * @dataProvider randomTimeStepTestDataForTestConstructor
     * @dataProvider specificTimeStepTestDataForTestConstructor
     * @dataProvider specificReferenceTimeTestDataForTestConstructor
     * @dataProvider timeStepAndReferenceTimeTestDataForTestConstructor
     *
     * @param array $args The arguments to pass to the constructor.
     * @param array $expectations An array whose keys are methods on the Totp instance to call and whose values are
     * either the expected return value, or an array containing the arguments for the method call and its expected
     * return value.
     * @param string|null $exceptionClass The exception that is expected from the constructor call, if any.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp constructor should only throw expected test exceptions.
     */
    public function testConstructor(array $args, array $expectations, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection Totp constructor should only throw expected test exceptions. */
        $totp = new Factory(...$args);

        foreach ($expectations as $method => $expected) {
            if (is_array($expected)) {
                $args     = $expected["args"];
                $expected = $expected["expected"];
            } else {
                $args = [];
            }

            $actual = $totp->$method(...$args);
            self::assertEquals($expected, $actual, "Return value from {$method}() not as expected.");
        }
    }

    /**
     * Test data for testSixDigits().
     *
     * @return Generator The RFC test data mapped to the correct structure for the test arguments.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public function dataForTestSixDigits(): iterable
    {
        yield from array_map(function (array $testData): array {
            return [
                $testData["secret"]["raw"],
                $testData["time-step"],
                $testData["referenceTimestamp"],
                $testData["algorithm"],
                [
                    "passwordAt" => [
                        "args" => [$testData["timestamp"]],
                        "value" => $testData["passwords"]["6"],
                    ],
                    "counterBytesAt" => [
                        "args" => [$testData["timestamp"]],
                        "value" => $testData["counterBytes"],
                    ],
                ],
            ];
        }, self::rfcTestData());

        // invalid secrets
        yield ["", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,];
        yield ["password-passwo", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,];
        yield [self::randomInvalidSecret(1), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,];
        yield [self::randomInvalidSecret(15), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,];

        // invalid time steps
        yield [self::randomValidSecret(20), 0, 0, HashAlgorithm::Sha1Algorithm, [], InvalidTimeStepException::class,];
        yield [self::randomValidSecret(20), -1, 0, HashAlgorithm::Sha1Algorithm, [], InvalidTimeStepException::class,];
        yield [self::randomValidSecret(20), -50, 0, HashAlgorithm::Sha1Algorithm, [], InvalidTimeStepException::class,];
        yield [self::randomValidSecret(20), PHP_INT_MIN, 0, HashAlgorithm::Sha1Algorithm, [], InvalidTimeStepException::class,];

        // invalid algorithms
        yield [self::randomValidSecret(20), 30, 0, "", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "foobar", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "md5", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHA1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "Sha1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHa1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHA1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "shA1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHa1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHA256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "Sha256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHa256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "shA256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHa256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHA256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "ShA256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHA512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "Sha512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHa512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "shA512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHa512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHA512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "ShA512", [], InvalidHashAlgorithmException::class,];

        // 100 random valid combinations
        for ($idx = 0; $idx < 100; ++$idx) {
            yield [
                self::randomValidSecret(64),
                10 * mt_rand(1, 360),
                mt_rand(0, time() - (20 * 365 * 24 * 60 * 60)),
                match (mt_rand(0, 2)) {
                    0 => HashAlgorithm::Sha1Algorithm,
                    1 => HashAlgorithm::Sha256Algorithm,
                    2 => HashAlgorithm::Sha512Algorithm,
                },
            ];
        }
    }

    /**
     * Test for Totp::sixDigits() factory method.
     *
     * @dataProvider dataForTestSixDigits
     *
     * @param string $secret The secret for the Totp.
     * @param int $timeStep The time step for the Totp.
     * @param int|\DateTime $referenceTime The reference time for the Totp.
     * @param string $hashAlgorithm The hash algorithm for the Totp.
     * @param array $expectations An array of expected return values from method calls. Each expectation is keyed with
     * the method name, and has a tuple of "args" and "value" as its value. The args element is an array of arguments to
     * provide in the method call; the value element is the expected return value.
     * @param string|null $exceptionClass
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::sixDigits() should only throw expected test exceptions.
     * DateTime constructor and Totp::password() should not throw with test data.
     */
    public function testSixDigits(string $secret, int $timeStep = TimeStep::DefaultTimeStep, int|DateTime $referenceTime = Factory::DefaultReferenceTime, string $hashAlgorithm = HashAlgorithm::DefaultAlgorithm, array $expectations = [], string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection Only throws if we're expecting a test exception */
        $totp = Factory::sixDigits(timeStep: new TimeStep($timeStep), referenceTime: $referenceTime, hashAlgorithm: new HashAlgorithm($hashAlgorithm))->totp(Secret::fromRaw($secret));
        self::assertEquals($secret, $totp->secret(), "Secret in Totp object does not match expected secret.");
        self::assertEquals($timeStep, $totp->timeStep()->seconds(), "TimeStep in Totp object does not match expected time step.");
        self::assertEquals($hashAlgorithm, $totp->hashAlgorithm()->algorithm(), "Hash algorithm in Totp object does not match expected algorithm.");

        if ($referenceTime instanceof DateTime) {
            $referenceTimestamp = $referenceTime->getTimestamp();
        } else {
            $referenceTimestamp = $referenceTime;
            /** @noinspection PhpUnhandledExceptionInspection Constructor doesn't throw with timestamp. */
            $referenceTime = new DateTime("@{$referenceTime}", new DateTimeZone("UTC"));
        }

        $renderer = $totp->renderer();
        self::assertInstanceOf(SixDigits::class, $renderer, "The Totp does not have the expected renderer type.");
        self::assertEquals(6, $renderer->digits()->quantity(), "The Totp renderer does not use the expected number of digits.");
        self::assertEquals($referenceTime, $totp->referenceTime(), "Reference DateTime in Totp object does not match expected DateTime.");
        self::assertEquals($referenceTimestamp, $totp->referenceTimestamp(), "Reference timestamp in Totp object does not match expected timestamp.");

        /** @noinspection PhpUnhandledExceptionInspection password should not throw with test data. */
        $password = $totp->password();
        self::assertEquals(6, strlen($password), "Password from Totp object is not 6 digits.");
        self::assertStringContainsOnly("0123456789", $password, "Password contains some invalid content.");

        foreach ($expectations as $methodName => $details) {
            try {
                $method = new ReflectionMethod($totp, $methodName);
                $method->setAccessible(true);
                $method   = $method->getClosure($totp);
                $expected = $details["value"];
                $actual   = $method(...$details["args"]);
                self::assertEquals($expected, $actual, "Expected return value from {$methodName} not found.");
            }
            catch (ReflectionException) {
                $this->fail("Invalid method name in expectations given to testSixDigitTotp().");
            }
        }
    }

    /**
     * Test data for testEightDigits().
     *
     * @return Generator The RFC test data mapped to the correct arrangement for the test arguments.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public function dataForTestEightDigits(): iterable
    {
        yield from array_map(function (array $testData): array {
            return [
                $testData["secret"]["raw"],
                $testData["time-step"],
                $testData["referenceTimestamp"],
                $testData["algorithm"],
                [
                    "passwordAt" => [
                        "args" => [$testData["timestamp"]],
                        "value" => $testData["passwords"]["8"],
                    ],
                    "counterBytesAt" => [
                        "args" => [$testData["timestamp"]],
                        "value" => $testData["counterBytes"],
                    ],
                ],
            ];
        }, self::rfcTestData());

        // invalid secrets
        yield ["", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,];
        yield ["password-passwo", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,];
        yield [self::randomInvalidSecret(1), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,];
        yield [self::randomInvalidSecret(15), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,];

        // invalid time steps
        yield [self::randomValidSecret(20), 0, 0, HashAlgorithm::Sha1Algorithm, [], InvalidTimeStepException::class,];
        yield [self::randomValidSecret(20), -1, 0, HashAlgorithm::Sha1Algorithm, [], InvalidTimeStepException::class,];
        yield [self::randomValidSecret(20), -50, 0, HashAlgorithm::Sha1Algorithm, [], InvalidTimeStepException::class,];
        yield [self::randomValidSecret(20), PHP_INT_MIN, 0, HashAlgorithm::Sha1Algorithm, [], InvalidTimeStepException::class,];

        // invalid algorithms
        yield [self::randomValidSecret(20), 30, 0, "", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "foobar", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "md5", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHA1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "Sha1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHa1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHA1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "shA1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHa1", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHA256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "Sha256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHa256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "shA256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHa256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHA256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "ShA256", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHA512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "Sha512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHa512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "shA512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "SHa512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "sHA512", [], InvalidHashAlgorithmException::class,];
        yield [self::randomValidSecret(20), 30, 0, "ShA512", [], InvalidHashAlgorithmException::class,];

        // 100 random valid combinations
        for ($idx = 0; $idx < 100; ++$idx) {
            yield [
                self::randomValidSecret(64),
                10 * mt_rand(1, 360),
                mt_rand(0, time() - (20 * 365 * 24 * 60 * 60)),
                match (mt_rand(0, 2)) {
                    0 => HashAlgorithm::Sha1Algorithm,
                    1 => HashAlgorithm::Sha256Algorithm,
                    2 => HashAlgorithm::Sha512Algorithm,
                },
            ];
        }
    }

    /**
     * Test for Totp::eightDigits() factory method.
     *
     * @dataProvider dataForTestEightDigits
     *
     * @param string $secret The secret for the Totp.
     * @param int $timeStep The time step for the Totp.
     * @param int|\DateTime $referenceTime The reference time for the Totp.
     * @param string $hashAlgorithm The hash algorithm for the Totp.
     * @param array $expectations An array of expected return values from method calls. Each expectation is keyed with
     * the method name, and has a tuple of "args" and "value" as its value. The args element is an array of arguments to
     * provide in the method call; the value element is the expected return value.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::eightDigits() should only throw expected test exceptions.
     * DateTime constructor and Totp::password() should not throw with test data.
     */
    public function testEightDigits(string $secret, int $timeStep = TimeStep::DefaultTimeStep, int|DateTime $referenceTime = Factory::DefaultReferenceTime, string $hashAlgorithm = HashAlgorithm::DefaultAlgorithm, array $expectations = [], string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection Only throws if we're expecting a test exception */
        $totp = Factory::eightDigits(timeStep: new TimeStep($timeStep), referenceTime: $referenceTime, hashAlgorithm: new HashAlgorithm($hashAlgorithm))->totp(Secret::fromRaw($secret));
        self::assertEquals($secret, $totp->secret(), "Secret in Totp object does not match expected secret.");
        self::assertEquals($timeStep, $totp->timeStep()->seconds(), "Time step in Totp object does not match expected time step.");
        self::assertEquals($hashAlgorithm, $totp->hashAlgorithm()->algorithm(), "Hash algorithm in Totp object does not match expected algorithm.");

        if ($referenceTime instanceof DateTime) {
            $referenceTimestamp = $referenceTime->getTimestamp();
        } else {
            $referenceTimestamp = $referenceTime;
            /** @noinspection PhpUnhandledExceptionInspection Constructor doesn't throw with timestamp. */
            $referenceTime = new DateTime("@{$referenceTime}", new DateTimeZone("UTC"));
        }

        self::assertInstanceOf(EightDigits::class, $totp->renderer(), "The Totp does not have the expected renderer type.");
        $renderer = $totp->renderer();
        self::assertInstanceOf(IntegerRenderer::class, $renderer, "The Totp does not have the expected renderer type.");
        self::assertEquals(8, $renderer->digits()->quantity(), "The Totp renderer does not use the expected number of digits.");
        self::assertEquals($referenceTime, $totp->referenceTime(), "Reference DateTime in Totp object does not match expected DateTime.");
        self::assertEquals($referenceTimestamp, $totp->referenceTimestamp(), "Reference timestamp in Totp object does not match expected timestamp.");

        /** @noinspection PhpUnhandledExceptionInspection password() should not throw with test data. */
        $password = $totp->password();
        self::assertEquals(8, strlen($password), "Password from Totp object is not 8 digits.");
        self::assertStringContainsOnly("0123456789", $password, "Password contains some invalid content.");

        foreach ($expectations as $methodName => $details) {
            try {
                $method = new ReflectionMethod($totp, $methodName);
                $method->setAccessible(true);
                $method   = $method->getClosure($totp);
                $expected = $details["value"];
                $actual   = $method(...$details["args"]);
                self::assertEquals($expected, $actual, "Expected return value from {$methodName} not found.");
            }
            catch (ReflectionException) {
                $this->fail("Invalid method name in expectations given to testSixDigitTotp().");
            }
        }
    }

    /**
     * Test data for testInteger().
     *
     * The test data consists of the RFC test data mapped to the correct structure for the test arguments, plus some
     * data to test specific scenarios, plus 100 random valid datasets.
     *
     * @return Generator The test data.
     * @throws \Exception if self::randomValidSecret() is not able to provide cryptographically-secure data.
     */
    public function dataForTestInteger(): iterable
    {
        $digits = 8;

        $extractTestData = function (array $testData) use (&$digits): array {
            return [
                $digits,
                $testData["secret"]["raw"],
                $testData["time-step"],
                $testData["referenceTimestamp"],
                $testData["algorithm"],
                [
                    "passwordAt" => [
                        "args" => [$testData["timestamp"]],
                        "value" => $testData["passwords"]["{$digits}"],
                    ],
                    "counterBytesAt" => [
                        "args" => [$testData["timestamp"]],
                        "value" => $testData["counterBytes"],
                    ],
                ],
            ];
        };

        yield from array_values(array_map($extractTestData, self::rfcTestData()));
        $digits = 7;
        yield from array_values(array_map($extractTestData, self::rfcTestData()));
        $digits = 6;
        yield from array_values(array_map($extractTestData, self::rfcTestData()));

        // invalid secrets
        yield from [
            [6, "", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [7, "", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [8, "", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [9, "", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [6, "password-passwo", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [7, "password-passwo", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [8, "password-passwo", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [9, "password-passwo", 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [6, self::randomInvalidSecret(1), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [7, self::randomInvalidSecret(1), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [8, self::randomInvalidSecret(1), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [9, self::randomInvalidSecret(1), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [6, self::randomInvalidSecret(15), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [7, self::randomInvalidSecret(15), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [8, self::randomInvalidSecret(15), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
            [9, self::randomInvalidSecret(15), 30, 0, HashAlgorithm::Sha1Algorithm, [], InvalidSecretException::class,],
        ];

        // 100 random valid combinations
        for ($idx = 0; $idx < 100; ++$idx) {
            yield [
                mt_rand(6, 9),
                self::randomValidSecret(64),
                10 * mt_rand(1, 360),
                mt_rand(0, time() - (20 * 365 * 24 * 60 * 60)),
                match (mt_rand(0, 2)) {
                    0 => HashAlgorithm::Sha1Algorithm,
                    1 => HashAlgorithm::Sha256Algorithm,
                    2 => HashAlgorithm::Sha512Algorithm,
                },
            ];
        }
    }

    /**
     * Test for Totp::eightDigits() factory method.
     *
     * @dataProvider dataForTestInteger
     *
     * @param mixed $digits The number of digits in generated passwords.
     * @param string $secret The secret for the Totp.
     * @param int $timeStep The time step for the Totp.
     * @param int|\DateTime $referenceTime The reference time for the Totp.
     * @param string $hashAlgorithm The hash algorithm for the Totp.
     * @param array $expectations An array of expected return values from method calls. Each expectation is keyed with
     * the method name, and has a tuple of "args" and "value" as its value. The args element is an array of arguments to
     * provide in the method call; the value element is the expected return value.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::integer() should only throw expected test exceptions. DateTime
     * constructor and Totp::password() should not throw with test data.
     */
    public function testInteger(mixed $digits, string $secret, int $timeStep = TimeStep::DefaultTimeStep, int|DateTime $referenceTime = Factory::DefaultReferenceTime, string $hashAlgorithm = HashAlgorithm::DefaultAlgorithm, array $expectations = [], string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection Only throws if we're expecting a test exception */
        $totp = Factory::integer(digits: new Digits($digits), timeStep: new TimeStep($timeStep), referenceTime: $referenceTime, hashAlgorithm: new HashAlgorithm($hashAlgorithm))->totp(Secret::fromRaw($secret));
        self::assertEquals($secret, $totp->secret(), "Secret in Totp object does not match expected secret.");
        self::assertEquals($timeStep, $totp->timeStep()->seconds(), "Time step in Totp object does not match expected time step.");
        self::assertEquals($hashAlgorithm, $totp->hashAlgorithm()->algorithm(), "Hash algorithm in Totp object does not match expected algorithm.");

        if ($referenceTime instanceof DateTime) {
            $referenceTimestamp = $referenceTime->getTimestamp();
        } else {
            $referenceTimestamp = $referenceTime;
            /** @noinspection PhpUnhandledExceptionInspection Constructor doesn't throw with timestamp. */
            $referenceTime = new DateTime("@{$referenceTime}", new DateTimeZone("UTC"));
        }

        $renderer = $totp->renderer();
        self::assertInstanceOf(Integer::class, $renderer, "The Totp does not have the expected renderer type.");
        self::assertEquals($digits, $renderer->digits()->quantity(), "The Totp renderer does not use the expected number of digits.");
        self::assertEquals($referenceTime, $totp->referenceTime(), "Reference DateTime in Totp object does not match expected DateTime.");
        self::assertEquals($referenceTimestamp, $totp->referenceTimestamp(), "Reference timestamp in Totp object does not match expected timestamp.");

        /** @noinspection PhpUnhandledExceptionInspection password() should not throw with test data. */
        $password = $totp->password();
        self::assertEquals($digits, strlen($password), "Password from Totp object is not {$digits} digits.");
        self::assertStringContainsOnly("0123456789", $password, "Password contains some invalid content.");

        foreach ($expectations as $methodName => $details) {
            try {
                $method = new ReflectionMethod($totp, $methodName);
                $method->setAccessible(true);
                $method   = $method->getClosure($totp);
                $expected = $details["value"];
                $actual   = $method(...$details["args"]);
                self::assertEquals($expected, $actual, "Expected return value from {$methodName} not found.");
            }
            catch (ReflectionException) {
                $this->fail("Invalid method name in expectations given to testSixDigitTotp().");
            }
        }
    }

    /**
     * Test data for testTotp1().
     *
     * @return array The test data.
     */
    public function dataForTestTotp1(): array
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
     * @param string $raw The raw secret.
     * @param string $base32 The expected Base32 for the raw secret.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::setSecret() shouldn't throw with test data.
     */
    #[DataProvider("dataForTestTotp1")]
    public function testTotp1(string $raw, string $base32): void
    {
        $factory = self::createFactory();
        /** @noinspection PhpUnhandledExceptionInspection setSecret() shouldn't throw with test data. */
        $totp = $factory->totp(Secret::fromRaw($raw));
        self::assertSame($base32, $totp->base32Secret(), "The base32 of the raw secret '" . self::hexOf($raw) . "' did not match the expected string.");
    }

    /**
     * Data provider for testSetHashAlgorithm().
     *
     * @return array The test data.
     */
    public function dataForTestSetHashAlgorithm(): array
    {
        return [
            "typicalSha1" => [HashAlgorithm::Sha1Algorithm,],
            "typicalSha256" => [HashAlgorithm::Sha256Algorithm,],
            "typicalSha512" => [HashAlgorithm::Sha512Algorithm,],
            "invalidStringMD5Upper" => ["MD5", InvalidHashAlgorithmException::class,],
            "invalidStringMD5Lower" => ["md5", InvalidHashAlgorithmException::class,],
            "invalidEmptyString" => ["", InvalidHashAlgorithmException::class,],
            "invalidNonsenseString" => ["foobarfizzbuzz", InvalidHashAlgorithmException::class,],
            "invalidEmpty" => ["", InvalidHashAlgorithmException::class,],
            "invalidSHA1-1" => ["SHA1", InvalidHashAlgorithmException::class,],
            "invalidSHA1-2" => ["Sha1", InvalidHashAlgorithmException::class,],
            "invalidSHA1-3" => ["sHa1", InvalidHashAlgorithmException::class,],
            "invalidSHA1-4" => ["shA1", InvalidHashAlgorithmException::class,],
            "invalidSHA1-5" => ["ShA1", InvalidHashAlgorithmException::class,],
            "invalidSHA1-6" => ["sHA1", InvalidHashAlgorithmException::class,],
            "invalidSHA1-7" => ["ShA1", InvalidHashAlgorithmException::class,],
            "invalidSHA256-1" => ["SHA256", InvalidHashAlgorithmException::class,],
            "invalidSHA256-2" => ["Sha256", InvalidHashAlgorithmException::class,],
            "invalidSHA256-3" => ["sHa256", InvalidHashAlgorithmException::class,],
            "invalidSHA256-4" => ["shA256", InvalidHashAlgorithmException::class,],
            "invalidSHA256-5" => ["ShA256", InvalidHashAlgorithmException::class,],
            "invalidSHA256-6" => ["sHA256", InvalidHashAlgorithmException::class,],
            "invalidSHA256-7" => ["ShA256", InvalidHashAlgorithmException::class,],
            "invalidSHA512-1" => ["SHA512", InvalidHashAlgorithmException::class,],
            "invalidSHA512-2" => ["Sha512", InvalidHashAlgorithmException::class,],
            "invalidSHA512-3" => ["sHa512", InvalidHashAlgorithmException::class,],
            "invalidSHA512-4" => ["shA512", InvalidHashAlgorithmException::class,],
            "invalidSHA512-5" => ["ShA512", InvalidHashAlgorithmException::class,],
            "invalidSHA512-6" => ["sHA512", InvalidHashAlgorithmException::class,],
            "invalidSHA512-7" => ["ShA512", InvalidHashAlgorithmException::class,],
            "invalidNull" => [null, TypeError::class,],
            "invalidInt0" => [0, TypeError::class,],
            "invalidInt1" => [1, TypeError::class,],
            "invalidInt256" => [256, TypeError::class,],
            "invalidInt512" => [512, TypeError::class,],
            "invalidFloat0.0" => [0.0, TypeError::class,],
            "invalidFloat1.0" => [1.0, TypeError::class,],
            "invalidFloat256.0" => [256.0, TypeError::class,],
            "invalidFloat512.0" => [512.0, TypeError::class,],
            "invalidStringableSha1" => [self::createStringable("Sha1"), TypeError::class,],
            "invalidStringableSha256" => [self::createStringable("Sha256"), TypeError::class,],
            "invalidStringableSha512" => [self::createStringable("Sha512"), TypeError::class,],
            "invalidArray" => [[HashAlgorithm::Sha1Algorithm,], TypeError::class,],
        ];
    }

    /**
     * Test the setHashAlgorithm() method.
     *
     * @dataProvider dataForTestSetHashAlgorithm
     *
     * @param mixed $algorithm The algorithm to set.
     * @param string|null $exceptionClass The type of exception expected to be thrown, if any.
     *
     * @noinspection PhpDocMissingThrowsInspection Totp::setHashAlgorithm() should only throw expected test exceptions.
     */
    public function testSetHashAlgorithm(mixed $algorithm, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection setHashAlgorithm() should only throw expected test exceptions. */
        $factory = self::createFactory()->withHashAlgorithm(new HashAlgorithm($algorithm));
        self::assertSame($algorithm, $factory->hashAlgorithm()->algorithm(), "The has algorithm was expected to be {$algorithm} but {$factory->hashAlgorithm()} was reported.");
    }

    /**
     * Data provider for testHashAlgorithm().
     *
     * @return array The test data.
     */
    public function dataForTestHashAlgorithm(): array
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
        $factory = self::createFactory();
        self::assertSame(HashAlgorithm::Sha1Algorithm, $factory->hashAlgorithm()->algorithm(), "The default hash algorithm was expected to be " . HashAlgorithm::Sha1Algorithm . " but {$factory->hashAlgorithm()->algorithm()} was reported.");
        /** @noinspection PhpUnhandledExceptionInspection setHashAlgorithm() shouldn't throw with test data. */
        $factory = $factory->withHashAlgorithm(new HashAlgorithm($algorithm));
        self::assertSame($algorithm, $factory->hashAlgorithm()->algorithm(), "The hash algorithm was expected to be {$algorithm} but {$factory->hashAlgorithm()->algorithm()} was reported.");
    }

    /**
     * Data provider for testSetReferenceTime()
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public function dataForTestSetReferenceTime(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection DateTime constructor shouldn't throw with test data. */
        return [
            "typicalEpochAsInt" => [0,],
            "typicalEpochAsDateTime" => [new DateTime("@0"),],
            "typicalEpochAsDateTimeUtc+4" => [new DateTime("@0", new DateTimeZone("UTC")),],
            "typicalNowAsTimestamp" => [time(),],
            "typical10YearsAgoAsTimestamp" => [time() - self::yearsInSeconds(10),],
            "typical10DaysAgoAsTimestamp" => [time() - self::daysInSeconds(10),],
            "typical10YearsAfterEpoch" => [self::yearsInSeconds(10),],
            "typical20YearsAfterEpoch" => [self::yearsInSeconds(20),],
            "typical30YearsAfterEpoch" => [self::yearsInSeconds(30),],
            "typical10SecondsAfterEpoch" => [self::daysInSeconds(10),],
            "typical20SecondsAfterEpoch" => [self::daysInSeconds(20),],
            "typical30SecondsAfterEpoch" => [self::daysInSeconds(30),],
            "typical40SecondsAfterEpoch" => [self::daysInSeconds(40),],
            "typical50SecondsAfterEpoch" => [self::daysInSeconds(50),],
            "typical60SecondsAfterEpoch" => [self::daysInSeconds(60),],
            "typical70SecondsAfterEpoch" => [self::daysInSeconds(70),],
            "typical80SecondsAfterEpoch" => [self::daysInSeconds(80),],
            "typical90SecondsAfterEpoch" => [self::daysInSeconds(90),],
            "typical100SecondsAfterEpoch" => [self::daysInSeconds(100),],

            // NOTE we don't use "now" because it creates a time with fractional seconds which aren't preserved in the
            // conversion to a unix timestamp, and which therefore causes a failed test assertion
            "typicalNowAsDateTime" => [new DateTime("@" . time()),],
            "typicalDateTimeUtc" => [new DateTime("23-04-1974", new DateTimeZone("UTC")),],
            "typicalDateTimeUtc-4" => [new DateTime("28-01-1978", new DateTimeZone("-0400")),],
            "typicalDateTimeUtc+4" => [new DateTime("19-07-2000", new DateTimeZone("+0400")),],
            "typicalDateTimeUtc-6" => [new DateTime("04-03-1984", new DateTimeZone("-0600")),],
            "typicalDateTimeUtc+6" => [new DateTime("31-12-1999", new DateTimeZone("+0600")),],
            "invalidNull" => [null, TypeError::class],
            "invalidEmptyString" => ["", TypeError::class],
            "invalidDateTimeParseableString" => ["now", TypeError::class],
        ];
    }

    /**
     * @dataProvider dataForTestSetReferenceTime
     *
     * @param int|\DateTime $time
     * @param string|null $exceptionClass
     */
    public function testSetReferenceTime(mixed $time, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $factory = self::createFactory()->withReferenceTime($time);

        if (is_int($time)) {
            self::assertSame($time, $factory->referenceTimestamp());
        } else {
            if ($time instanceof DateTime) {
                self::assertInstanceOf(DateTime::class, $factory->referenceTime(), "referenceTime() failed to return a DateTime object with input DateTime '" . $time->format("Y-m-d H:i:s") . "'");
                self::assertEquals($time, $factory->referenceTime());
            }
        }
    }

    /**
     * Date provider for dataForTestReferenceTimestamp().
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public function dataForTestReferenceTimestamp(): array
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

        $factory = self::createFactory()->withReferenceTime($time);
        self::assertSame($expectedTimestamp, $factory->referenceTimestamp());
    }

    /**
     * Date provider for testReferenceTime().
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection DateTime constructor shouldn't throw with test data.
     */
    public function dataForTestReferenceTime(): array
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

        $factory = self::createFactory()->withReferenceTime($time);
        $actual  = $factory->referenceTime();
        self::assertInstanceOf(DateTime::class, $actual);
        self::assertEquals($expectedDateTime, $actual);
    }

    /**
     * Data provider for testSetTimeStep()
     *
     * @return array The test data.
     */
    public function dataForTestSetTimeStep(): array
    {
        return [
            "typical30" => [30,],
            "typical60" => [60,],
            "typical10" => [10,],
            "typical20" => [20,],

            // these type casts should both result in (int) 0 - PHP type casts just truncate floats
            "invalidFloat0.99CastInt" => [(int)0.99, InvalidTimeStepException::class],
            "invalidFloat0.49CastInt" => [(int)0.49, InvalidTimeStepException::class],
            "invalidFloat0.49" => [0.49, TypeError::class,],
            "invalidFloat0.51" => [0.51, TypeError::class,],
            "invalid0" => [0, InvalidTimeStepException::class,],
            "invalidMinus1" => [-1, InvalidTimeStepException::class,],
            "invalidMinus30" => [-30, InvalidTimeStepException::class,],
            "invalidNull" => [null, TypeError::class,],
            "invalidString" => ["30", TypeError::class,],
            "invalidObject" => [new class
            {
            }, TypeError::class,],
        ];
    }

    /**
     * Test for setTimeStep() method.
     *
     * @dataProvider dataForTestSetTimeStep
     *
     * @param mixed $timeStep The time step to set.
     * @param class-string|null $exceptionClass The type of exception that is expected, if any.
     *
     * @noinspection PhpDocMissingThrowsInspection totp::setTimeStep() should only throw expected test exceptions.
     */
    public function testSetTimeStep(mixed $timeStep, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        /** @noinspection PhpUnhandledExceptionInspection setTimeStep() should only throw expected test exceptions. */
        $factory = self::createFactory()->withTimeStep(new TimeStep($timeStep));
        self::assertSame($timeStep, $factory->timeStep()->seconds(), "The time step {$timeStep} was expected but {$factory->timeStep()->seconds()} was reported.");
    }

    /**
     * Data provider for testTimeStep()
     *
     * @return Generator The test data.
     */
    public function dataForTestTimeStep(): iterable
    {
        // test with all valid time steps up to 1 hour
        for ($timeStep = 1; $timeStep <= 3600; ++$timeStep) {
            yield [$timeStep,];
        }

        // throw some random valid time steps at it for good measure
        for ($idx = 0; $idx < 5000; ++$idx) {
            yield [mt_rand(1, 3600),];
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
        /** @noinspection PhpUnhandledExceptionInspection setTimeStep() shouldn't throw with test data. */
        $factory = self::createFactory()->withTimeStep(new TimeStep($timeStep));
        self::assertSame($timeStep, $factory->timeStep()->seconds(), "The time step {$timeStep} was expected but {$factory->timeStep()} was reported.");
    }

    /**
     * Test data for testSetRenderer()
     *
     * @return array The test data.
     * @noinspection PhpDocMissingThrowsInspection Integer renderer constructor does not throw in these cases.
     */
    public function dataForTestSetRenderer(): array
    {
        /** @noinspection PhpUnhandledExceptionInspection Integer renderer constructor does not throw in these cases. */
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
            "invalidNull" => [null, TypeError::class,],
            "invalidInt" => [6, TypeError::class,],
            "invalidFloat" => [6.5, TypeError::class,],
            "invalidString" => ["foo", TypeError::class,],
            "invalidObject" => [new class
            {
            }, TypeError::class,],
            "invalidArray" => [["render" => function (string $hmac): string {
                return "insecure";
            }], TypeError::class,],
            "invalidStdClass" => [(object)["render" => function (string $hmac): string {
                return "insecure";
            }], TypeError::class,],
        ];
    }

    /**
     * @dataProvider dataForTestSetRenderer
     *
     * @param mixed $renderer The renderer to set.
     * @param string|null $exceptionClass The class name of an exception that is expected to be thrown, if any.
     */
    public function testSetRenderer(mixed $renderer, ?string $exceptionClass = null): void
    {
        if (isset($exceptionClass)) {
            $this->expectException($exceptionClass);
        }

        $factory = self::createFactory()->withRenderer($renderer);
        self::assertSame($renderer, $factory->renderer(), "Renderer set was not returned from renderer() method.");
    }

    /**
     * Test data for testSetRenderer()
     *
     * @return array
     * @noinspection PhpDocMissingThrowsInspection Integer renderer constructor shouldn't throw with test data.
     */
    public function dataForTestRenderer(): array
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
        $factory = self::createFactory()->withRenderer($renderer);
        self::assertSame($renderer, $factory->renderer(), "Unexpected object returned from renderer() method.");
    }

    /**
     * Test the defaultRenderer() method.
     */
    public function testDefaultRenderer(): void
    {
        $defaultRenderer = new ReflectionMethod(Factory::class, "defaultRenderer");
        $defaultRenderer->setAccessible(true);
        $defaultRenderer = $defaultRenderer->getClosure();
        $renderer        = $defaultRenderer();
        self::assertInstanceOf(SixDigits::class, $renderer);
    }

    /**
     * Test the randomSecret() method.
     * @throws \Equit\Totp\Exceptions\SecureRandomDataUnavailableException if Totp::randomSecret() is unable to provide
     * cryptographically-secure random data.
     */
    public function testRandomSecret(): void
    {
        // NOTE can't test case where randomSecret() throws because we can't force random_bytes() to throw
        for ($idx = 0; $idx < 100; ++$idx) {
            self::assertGreaterThanOrEqual(64, strlen(Factory::randomSecret()->raw()), "randomSecret() did not return a sufficiently large byte sequence.");
        }
    }
}
