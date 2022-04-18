<?php

/**
 * Use the oathtool utility (https://www.nongnu.org/oath-toolkit/oathtool.1.html) to generate PHP test data for the
 * RFC 6238 test data (see page 15 of the RFC).
 *
 * The test data in the RFC all use the same secret, reference time (0) and interval (30).
 *
 * The oathtool command is expected to be in your path. If it is not, this script will fail.
 */
use Equit\Totp\Base32;
use Equit\Totp\Base64;

require_once("bootstrap.php");

/**
 * Show the usage/help message.
 */
function usage(): void
{
	global $argv;
	$bin = basename($argv[0]);

	echo <<<EOT
{$bin} - Generate test data for php-totp's unit tests based on the test data in RFC 6238.

Usage: {$argv[0]} [--help]

The oathtool command must be in your path. If it's not, this script will fail.

--help
    Show this help message and exit.

EOT;
}

if (isset($argv[1]) && "--help" === $argv[1]) {
	usage();
	exit(1);
}

$secret = "12345678901234567890";
$base32secret = Base32::encode($secret);
$base64secret = Base64::encode($secret);

echo "[\n";

foreach (["sha1", "sha256", "sha512"] as $algorithm) {
	foreach ([59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000,] as $timestamp) {
		$time = new DateTime("@{$timestamp}", new DateTimeZone("UTC"));
		$otp  = trim(`oathtool -b -d 8 --now="{$time->format("Y-m-d H:i:s")} UTC" --totp="{$algorithm}" "{$base32secret}"`);
		$otp7 = substr($otp, 1);
		$otp6 = substr($otp, 2);

        // NOTE the secret is ASCII-safe, so we can output it without escaping any binary
		echo <<<EOT
    "rfcTestData-{$algorithm}-{$timestamp}" => [
      "algorithm" => "${algorithm}",
      "referenceTimestamp" => 0,
      "referenceTime" => new DateTime("1970-01-01 00:00:00", new DateTimeZone("UTC")),
      "interval" => 30,
      "timestamp" => {$timestamp},
      "time" => new DateTime("{$time->format("Y-m-d H:i:s")}", new DateTimeZone("UTC")),
      "secret" => [
        "raw" => "{$secret}",
        "base32" => "{$base32secret}",
        "base64" => "{$base64secret}",
      ],
      "passwords" => [
        "8" => "{$otp}",
        "7" => "{$otp7}",
        "6" => "{$otp6}",
      ],
    ],

EOT;
    }
}

echo "];\n";