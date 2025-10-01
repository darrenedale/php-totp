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

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;

use function Equit\Totp\scrubString;

#[CoversFunction("Equit\Totp\scrubString")]
final class FunctionsTest extends Framework\TestCase
{
    /** Data provider with strings to scrub for testScrubString1(). */
    public static function providerTestScrubString1(): iterable
    {
        yield "typical" => ["foobarfizzbuzz",];
        yield "whitespace" => ["        ",];
        yield "nulls" => ["\0\0\0\0\0\0\0\0",];
        yield "empty" => ["",];
        yield "very-long" => [str_repeat("foobarfizzbuzz", 10000),];
    }

    /** Ensure strings are successfully scrubbed. */
    #[DataProvider("providerTestScrubString1")]
    public function testScrubString1(mixed $str): void
    {
        $before = $str;
        scrubString($str);
        self::assertIsString($str, "Scrubbing the string changed its type.");
        self::assertAllCharactersHaveChanged($before, $str, "Not all the characters in the string were changed by scrubString().");
    }
}