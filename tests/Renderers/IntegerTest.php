<?php
/*
 * Copyright 2022 Darren Edale
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

namespace Equit\Totp\Tests\Renderers;

use Equit\Totp\Exceptions\InvalidDigitsException;
use Equit\Totp\Renderers\Integer;
use Equit\Totp\Tests\Framework\TestCase;

/**
 * Test case for Integer Totp renderer.
 */
class IntegerTest extends TestCase
{
	/**
	 * Data provider for testConstructor().
	 *
	 * @return array The test data.
	 */
	public function dataForTestConstructor(): array
	{
		return [
			"typicalSix" => [6,],
			"typicalEight" => [8,],
			"extremeTen" => [10,],
			"extremeFifty" => [50,],
			"invalidFive" => [5, InvalidDigitsException::class,],
			"invalidOne" => [1, InvalidDigitsException::class,],
			"invalidZero" => [0, InvalidDigitsException::class,],
			"invalidMinus1" => [-1, InvalidDigitsException::class,],
			"invalidMinusFifty" => [-50, InvalidDigitsException::class,],
			"invalidPhpIntMin" => [PHP_INT_MIN, InvalidDigitsException::class,],
		];
	}

	/**
	 * Test the integer renderer's constructor.
	 *
	 * @dataProvider dataForTestConstructor
	 *
	 * @param mixed $digits The number of digits for the integer renderer.
	 * @param class-string|null $exceptionClass Class of exception expected, if any. Default is null.
	 */
	public function testConstructor(mixed $digits, ?string $exceptionClass = null)
	{
		if (isset($exceptionClass)) {
			$this->expectException($exceptionClass);
		}

		$renderer = new Integer($digits);

		if (!isset($exceptionClass)) {
			$this->assertSame($digits, $renderer->digits());
		}
	}

	/**
	 * Data provider for testRender().
	 *
	 * @return array[] The test data.
	 */
	public function dataForTestRender(): array
	{
		return [
			// max 31-bit unsigned int
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "483647",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "7483647",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "47483647",],

			// min 31-bit unsigned int (i.e. 0)
			[6, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "000000",],
			[7, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "0000000",],
			[8, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "00000000",],

			// offset = 0, padding with 5 0s
			[6, "\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00", "000001",],
			[7, "\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00", "0000001",],
			[8, "\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00", "00000001",],

			// padding, increasing offset, shifting hex digit 1 in 31-bit BE unsigned int (i.e. 0x00000001, 0x00000010,
			// 0x00000011, 0x00000100, 0x00000101, ... 0x00001111)
			[6, "\xff\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", "000001",],
			[7, "\xff\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", "0000001",],
			[8, "\xff\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", "00000001",],
			[6, "\xff\xff\x00\x00\x00\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02", "000016",],
			[7, "\xff\xff\x00\x00\x00\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02", "0000016",],
			[8, "\xff\xff\x00\x00\x00\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02", "00000016",],
			[6, "\xff\xff\xff\x00\x00\x00\x11\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x03", "000017",],
			[7, "\xff\xff\xff\x00\x00\x00\x11\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x03", "0000017",],
			[8, "\xff\xff\xff\x00\x00\x00\x11\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x03", "00000017",],
			[6, "\xff\xff\xff\xff\x00\x00\x01\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x04", "000256",],
			[7, "\xff\xff\xff\xff\x00\x00\x01\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x04", "0000256",],
			[8, "\xff\xff\xff\xff\x00\x00\x01\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x04", "00000256",],
			[6, "\xff\xff\xff\xff\xff\x00\x00\x01\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x05", "000257",],
			[7, "\xff\xff\xff\xff\xff\x00\x00\x01\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x05", "0000257",],
			[8, "\xff\xff\xff\xff\xff\x00\x00\x01\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x05", "00000257",],
			[6, "\xff\xff\xff\xff\xff\xff\x00\x00\x01\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x06", "000272",],
			[7, "\xff\xff\xff\xff\xff\xff\x00\x00\x01\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x06", "0000272",],
			[8, "\xff\xff\xff\xff\xff\xff\x00\x00\x01\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x06", "00000272",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\x00\x00\x01\x11\xff\xff\xff\xff\xff\xff\xff\xff\x07", "000273",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\x00\x00\x01\x11\xff\xff\xff\xff\xff\xff\xff\xff\x07", "0000273",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\x00\x00\x01\x11\xff\xff\xff\xff\xff\xff\xff\xff\x07", "00000273",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x00\xff\xff\xff\xff\xff\xff\xff\x08", "004096",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x00\xff\xff\xff\xff\xff\xff\xff\x08", "0004096",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x00\xff\xff\xff\xff\xff\xff\xff\x08", "00004096",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x01\xff\xff\xff\xff\xff\xff\x09", "004097",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x01\xff\xff\xff\xff\xff\xff\x09", "0004097",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x01\xff\xff\xff\xff\xff\xff\x09", "00004097",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x10\xff\xff\xff\xff\xff\x0a", "004112",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x10\xff\xff\xff\xff\xff\x0a", "0004112",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x10\xff\xff\xff\xff\xff\x0a", "00004112",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x11\xff\xff\xff\xff\x0b", "004113",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x11\xff\xff\xff\xff\x0b", "0004113",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x11\xff\xff\xff\xff\x0b", "00004113",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x00\xff\xff\xff\x0c", "004352",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x00\xff\xff\xff\x0c", "0004352",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x00\xff\xff\xff\x0c", "00004352",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x01\xff\xff\x0d", "004353",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x01\xff\xff\x0d", "0004353",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x01\xff\xff\x0d", "00004353",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x10\xff\x0e", "004368",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x10\xff\x0e", "0004368",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x10\xff\x0e", "00004368",],
			[6, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x11\x0f", "004369",],
			[7, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x11\x0f", "0004369",],
			[8, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x11\x0f", "00004369",],

			// test offset masking at byte 19 - all should produce an offset of 8
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x08", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x08", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x08", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x18", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x18", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x18", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x28", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x28", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x28", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x38", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x38", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x38", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x48", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x48", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x48", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x58", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x58", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x58", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x68", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x68", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x68", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x78", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x78", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x78", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x88", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x88", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x88", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x98", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x98", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x98", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xa8", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xa8", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xa8", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xb8", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xb8", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xb8", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xc8", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xc8", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xc8", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xd8", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xd8", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xd8", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xe8", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xe8", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xe8", "16909060",],
			[6, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xf8", "909060",],
			[7, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xf8", "6909060",],
			[8, "\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xf8", "16909060",],

			// some semi-random HMACs
			[6, "\xe2\xfd\xbb\xb7\x75\xce\xf7\xaa\x91\xee\xfe\x01\xea\x1e\x52\xae\x1c\x9c\xb2\x9a", "054686",],
			[6, "\x30\x57\xc3\x9a\xd1\x8c\xcd\x08\x15\xb1\x73\x3a\x2d\x11\x00\xc4\x20\x50\xf2\x8b", "032000",],
			[6, "\x8c\x86\x7f\x32\x32\x85\x0c\x6e\x64\xf7\x6c\x06\x89\xba\x8a\xa3\x34\x4b\x7d\x03", "171660",],
			[7, "\x8c\x86\x7f\x32\x32\x85\x0c\x6e\x64\xf7\x6c\x06\x89\xba\x8a\xa3\x34\x4b\x7d\x03", "2171660",],
			[8, "\x8c\x86\x7f\x32\x32\x85\x0c\x6e\x64\xf7\x6c\x06\x89\xba\x8a\xa3\x34\x4b\x7d\x03", "42171660",],
			[6, "\x66\x1c\x99\x76\xdd\x47\x3e\xe0\x27\x76\xab\x8b\xb1\x3b\x8e\xe3\x0d\x95\x8d\x9f", "834637",],
			[7, "\x66\x1c\x99\x76\xdd\x47\x3e\xe0\x27\x76\xab\x8b\xb1\x3b\x8e\xe3\x0d\x95\x8d\x9f", "1834637",],
			[8, "\x66\x1c\x99\x76\xdd\x47\x3e\xe0\x27\x76\xab\x8b\xb1\x3b\x8e\xe3\x0d\x95\x8d\x9f", "61834637",],
			[6, "\x03\x80\xde\xcd\xff\x60\xdb\x19\xea\x5d\x59\x75\xca\xf7\xa0\xef\x3b\x25\xda\x53", "582107",],
			[7, "\x03\x80\xde\xcd\xff\x60\xdb\x19\xea\x5d\x59\x75\xca\xf7\xa0\xef\x3b\x25\xda\x53", "8582107",],
			[8, "\x03\x80\xde\xcd\xff\x60\xdb\x19\xea\x5d\x59\x75\xca\xf7\xa0\xef\x3b\x25\xda\x53", "08582107",],
			[6, "\xcd\x83\x00\x7f\x55\x64\x2f\x3f\xae\x94\xc8\x14\x12\x25\x74\xd1\xbb\x7c\xb9\xe2", "344932",],
			[7, "\xcd\x83\x00\x7f\x55\x64\x2f\x3f\xae\x94\xc8\x14\x12\x25\x74\xd1\xbb\x7c\xb9\xe2", "8344932",],
			[8, "\xcd\x83\x00\x7f\x55\x64\x2f\x3f\xae\x94\xc8\x14\x12\x25\x74\xd1\xbb\x7c\xb9\xe2", "08344932",],
			[6, "\x47\xb5\x1c\xf4\xa4\xbd\xae\x77\x97\x81\x80\x2b\x23\x7a\xc8\x72\x0e\x0d\xe2\xa8", "362923",],
			[7, "\x47\xb5\x1c\xf4\xa4\xbd\xae\x77\x97\x81\x80\x2b\x23\x7a\xc8\x72\x0e\x0d\xe2\xa8", "4362923",],
			[8, "\x47\xb5\x1c\xf4\xa4\xbd\xae\x77\x97\x81\x80\x2b\x23\x7a\xc8\x72\x0e\x0d\xe2\xa8", "94362923",],
			[6, "\x91\x4c\x49\x20\xdd\xe5\xd3\x2d\x10\xf6\xaa\x31\x0a\xd2\x86\xf4\xee\xdc\xd0\x7f", "811152",],
			[7, "\x91\x4c\x49\x20\xdd\xe5\xd3\x2d\x10\xf6\xaa\x31\x0a\xd2\x86\xf4\xee\xdc\xd0\x7f", "1811152",],
			[8, "\x91\x4c\x49\x20\xdd\xe5\xd3\x2d\x10\xf6\xaa\x31\x0a\xd2\x86\xf4\xee\xdc\xd0\x7f", "61811152",],
			[6, "\x69\x0e\x9c\x6e\x9e\x17\xee\x85\x69\xec\x9e\x81\x02\x3b\x1d\xf1\x71\x8c\x71\xaf", "266929",],
			[7, "\x69\x0e\x9c\x6e\x9e\x17\xee\x85\x69\xec\x9e\x81\x02\x3b\x1d\xf1\x71\x8c\x71\xaf", "3266929",],
			[8, "\x69\x0e\x9c\x6e\x9e\x17\xee\x85\x69\xec\x9e\x81\x02\x3b\x1d\xf1\x71\x8c\x71\xaf", "03266929",],
			[6, "\x19\x0f\x55\x70\x5e\x87\x5d\xdb\x67\xaa\x2a\x2d\x9c\x75\x05\x7c\x29\x85\x87\x99", "407260",],
			[7, "\x19\x0f\x55\x70\x5e\x87\x5d\xdb\x67\xaa\x2a\x2d\x9c\x75\x05\x7c\x29\x85\x87\x99", "7407260",],
			[8, "\x19\x0f\x55\x70\x5e\x87\x5d\xdb\x67\xaa\x2a\x2d\x9c\x75\x05\x7c\x29\x85\x87\x99", "07407260",],
//			[6, "", "",],
//			[7, "", "",],
//			[8, "", "",],
		];
	}

	/**
	 * Test the integer renderer's render() method.
	 *
	 * @dataProvider dataForTestRender
	 *
	 * @param int $digits The number of digits to render in the password.
	 * @param string $hmac The HMAC to use to render the password.
	 * @param string $expectedPassword The password the renderer is expected to produce.
	 */
	public function testRender(int $digits, string $hmac, string $expectedPassword)
	{
		$renderer = new Integer($digits);
		$actualPassword = $renderer->render($hmac);
		$this->assertSame($digits, strlen($actualPassword), "{$digits}-digit renderer produced a password of " . strlen($actualPassword) . " digits.");
		$this->assertStringContainsOnly("0123456789", $actualPassword, "Renderer produced a non-decimal password.");
		$this->assertSame($expectedPassword, $actualPassword, "Renderer produced an incorrect password.");
	}
}
