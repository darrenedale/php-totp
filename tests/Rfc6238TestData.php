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

use DateTime;
use DateTimeZone;

final class Rfc6238TestData
{
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
    public static function rfcTestData(): iterable
    {
        yield "rfcTestData-sha1-59" => [
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
        ];
        yield "rfcTestData-sha1-1111111109" => [
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
        ];
        yield "rfcTestData-sha1-1111111111" => [
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
        ];
        yield "rfcTestData-sha1-1234567890" => [
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
        ];
        yield "rfcTestData-sha1-2000000000" => [
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
        ];
        yield "rfcTestData-sha1-20000000000" => [
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
        ];
        yield "rfcTestData-sha256-59" => [
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
        ];
        yield "rfcTestData-sha256-1111111109" => [
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
        ];
        yield "rfcTestData-sha256-1111111111" => [
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
        ];
        yield "rfcTestData-sha256-1234567890" => [
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
        ];
        yield "rfcTestData-sha256-2000000000" => [
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
        ];
        yield "rfcTestData-sha256-20000000000" => [
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
        ];
        yield "rfcTestData-sha512-59" => [
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
        ];
        yield "rfcTestData-sha512-1111111109" => [
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
        ];
        yield "rfcTestData-sha512-1111111111" => [
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
        ];
        yield "rfcTestData-sha512-1234567890" => [
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
        ];
        yield "rfcTestData-sha512-2000000000" => [
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
        ];
        yield "rfcTestData-sha512-20000000000" => [
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
        ];
    }
}
