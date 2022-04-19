<?php

namespace Equit\Totp\Tests\Renderers;

use Equit\Totp\Renderers\EightDigits;
use Equit\Totp\Tests\TestCase;

class EightDigitTest extends TestCase
{
	/**
	 * Test the renderer's constructor.
	 */
	public function testConstructor()
	{
		$renderer = new EightDigits();
		$this->assertSame($renderer->digits(), 8, "EightDigits renderer must return 8 from digits() at all times.");
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
			["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", "47483647",],

			// min 31-bit unsigned int (i.e. 0)
			["\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "00000000",],

			// offset = 0, padding with 5 0s
			["\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00", "00000001",],

			// padding, increasing offset, shifting hex digit 1 in 31-bit BE unsigned int (i.e. 0x00000001, 0x00000010,
			// 0x00000011, 0x00000100, 0x00000101, ... 0x00001111)
			["\xff\x00\x00\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", "00000001",],
			["\xff\xff\x00\x00\x00\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02", "00000016",],
			["\xff\xff\xff\x00\x00\x00\x11\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x03", "00000017",],
			["\xff\xff\xff\xff\x00\x00\x01\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x04", "00000256",],
			["\xff\xff\xff\xff\xff\x00\x00\x01\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x05", "00000257",],
			["\xff\xff\xff\xff\xff\xff\x00\x00\x01\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\x06", "00000272",],
			["\xff\xff\xff\xff\xff\xff\xff\x00\x00\x01\x11\xff\xff\xff\xff\xff\xff\xff\xff\x07", "00000273",],
			["\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x00\xff\xff\xff\xff\xff\xff\xff\x08", "00004096",],
			["\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x01\xff\xff\xff\xff\xff\xff\x09", "00004097",],
			["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x10\xff\xff\xff\xff\xff\x0a", "00004112",],
			["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x10\x11\xff\xff\xff\xff\x0b", "00004113",],
			["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x00\xff\xff\xff\x0c", "00004352",],
			["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x01\xff\xff\x0d", "00004353",],
			["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x10\xff\x0e", "00004368",],
			["\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x11\x11\x0f", "00004369",],

			// test offset masking at byte 19 - all should produce an offset of 8
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x08", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x18", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x28", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x38", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x48", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x58", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x68", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x78", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x88", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\x98", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xa8", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xb8", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xc8", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xd8", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xe8", "16909060",],
			["\x43\x82\x1f\x68\xf2\xda\x10\xbc\x01\x02\x03\x04\xa7\x1c\xff\xef\x01\xba\xd6\xf8", "16909060",],

			// some semi-random HMACs
			["\x8c\x86\x7f\x32\x32\x85\x0c\x6e\x64\xf7\x6c\x06\x89\xba\x8a\xa3\x34\x4b\x7d\x03", "42171660",],
			["\x66\x1c\x99\x76\xdd\x47\x3e\xe0\x27\x76\xab\x8b\xb1\x3b\x8e\xe3\x0d\x95\x8d\x9f", "61834637",],
			["\x03\x80\xde\xcd\xff\x60\xdb\x19\xea\x5d\x59\x75\xca\xf7\xa0\xef\x3b\x25\xda\x53", "08582107",],
			["\xcd\x83\x00\x7f\x55\x64\x2f\x3f\xae\x94\xc8\x14\x12\x25\x74\xd1\xbb\x7c\xb9\xe2", "08344932",],
			["\x47\xb5\x1c\xf4\xa4\xbd\xae\x77\x97\x81\x80\x2b\x23\x7a\xc8\x72\x0e\x0d\xe2\xa8", "94362923",],
			["\x91\x4c\x49\x20\xdd\xe5\xd3\x2d\x10\xf6\xaa\x31\x0a\xd2\x86\xf4\xee\xdc\xd0\x7f", "61811152",],
			["\x69\x0e\x9c\x6e\x9e\x17\xee\x85\x69\xec\x9e\x81\x02\x3b\x1d\xf1\x71\x8c\x71\xaf", "03266929",],
			["\x19\x0f\x55\x70\x5e\x87\x5d\xdb\x67\xaa\x2a\x2d\x9c\x75\x05\x7c\x29\x85\x87\x99", "07407260",],
//			["", "",],
		];
	}

	/**
	 * Test the integer renderer's render() method.
	 *
	 * @dataProvider dataForTestRender
	 *
	 * @param string $hmac The HMAC to use to render the password.
	 * @param string $expectedPassword The password the renderer is expected to produce.
	 */
	public function testRender(string $hmac, string $expectedPassword)
	{
		$renderer = new EightDigits();
		$actualPassword = $renderer->render($hmac);
		$this->assertSame(8, strlen($actualPassword), "EightDigits renderer produced a password of " . strlen($actualPassword) . " digits.");
		$this->assertStringContainsOnly("0123456789", $actualPassword, "Renderer produced a non-decimal password.");
		$this->assertSame($expectedPassword, $actualPassword, "Renderer produced an incorrect password.");
	}
}