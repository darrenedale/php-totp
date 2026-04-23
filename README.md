# php-totp

[![Unit Tests](https://github.com/darrenedale/php-totp/actions/workflows/run-tests.yml/badge.svg)](https://github.com/darrenedale/php-totp/actions/workflows/run-tests.yml)

Time-based One Time Password Generator for PHP.

Add two-factor authentication to your app using RFC 6238-compliant TOTP, compatible with commonly-available
authenticator apps such as Google Authenticator, KeePassXC, Microsoft Authenticator and more.

## Quick start

1. Generate a secure, random secret for your user:

    ```php
    use CitrusLab\Totp\Factory;

    $user->totpSecret = Factory::randomSecret()->raw()
    ```

2. Notify the user of the details of their TOTP for them to import into their authenticator app:

    ```php
    use CitrusLab\Totp\Factory;
    use CitrusLab\Totp\UrlGenerator;

    $factory = new Factory();
    UrlGenerator::for($user->username)->urlFor($factory->totp(new Secret($user->totpSecret)))
    ```

3. When a user logs in, ask them for their current TOTP and verify it:

    ```php
    use CitrusLab\Totp\Factory;

    $factory = new Factory();
    $factory->totp(new Secret($user->totpSecret))->verify($inputOtp)
    ```

## Contents

- [Provisioning TOTP for users](README.md#provisioning-totp-for-users)
   - [Generating secrets](README.md#generating-secrets)
   - [Notifying users](README.md#notifying-users)
   - [Verifying successful provisioning](README.md#verifying-successful-provisioning)
- [Authenticating](README.md#authenticating)
   - [Ensuring OTPs are used only once](README.md#ensuring-otps-are-used-only-once)
- [Custom TOTP Configurations](README.md#custom-totp-configurations)
   - [Hashing algorithms](README.md#hashing-algorithms)
   - [Password digits](README.md#password-digits)
   - [Reference timestamp and time step](README.md#reference-timestamp-and-time-step)
- [Base32/Base64 secrets](README.md#base32base64-secrets)

## See also

- [Secrets.md](Secrets.md)
- [API.md](API.md)

## Introduction

TOTP is specified in [RFC 6238](https://www.ietf.org/rfc/rfc6238.txt) and builds on
[HMAC-based One-Time Passwords (HOTP, RFC4226)](https://www.ietf.org/rfc/rfc4226.txt) by computing a
[Hashed Message Authentication Code (HMAC, RFC 2104)](https://www.ietf.org/rfc/rfc2104.txt) based on a count of the
number of time steps that have elapsed since a given point in time and a random secret that is known by the
authorising server (your app) and a secure client app (your users' authenticator apps). A 31-bit integer is then derived
from the HMAC and the rightmost (usually 6) decimal digits are used as the password (padded with 0s if required). As
long as the server and app agree on the current time, the reference time, the size of the time step and the secret, they
both calculate the same sequence of passwords at the same time.

The _Totp_ library consists of four main components: a `Totp` class, which calculates TOTPs; a `Factory` class that
provides access to `Totp` calculator instances; a collection of OTP `Renderer` classes that turn the result of the
calculation performed by `Totp` into actual one-time passwords; and an `UrlGenerator` class, which helps generate the
information the user needs to set up their authenticator app.

The examples below use notional functions, classes and methods to fill in the functionality that is outside the scope of
the _Totp_ library. For example, the `encrypt()` function is used as a placeholder for whatever mechanism your
app uses to encrypt data. They also assume a standard TOTP setup as described in RFC 6238 - that is, a reference time
of 00:00:00 on 01/01/1970, a time step of 30 seconds and the SHA1 hashing algorithm producing 6-digit passwords.
Possibilities for customising the TOTP setup are described later.

## Provisioning TOTP for Users

There are three steps involved in provisioning a user with TOTP:

1. [Generate, encrypt and store a secret](README.md#generating-secrets) for the user.
2. [Send the user a notification](README.md#notifying-users) with a URL, secret and/or QR code they can import into
   their authenticator app.
3. [Verify successful provisioning](README.md#verifying-successful-provisioning) by asking the user for their current
   OTP.

### Generating secrets

The TOTP specification mandates that secrets are generated randomly (i.e. not chosen by the user). You can generate your
own secrets, but _Totp_ provides a method - `Factory::randomSecret()` that will generate a random secret
for you that is guaranteed to be cryptographically secure and strong enough for all the hashing algorithms supported.

_Totp_ used a named type to represent secrets to prevent use of invalid secrets and to ensure that the content of the
secret is always securely erased when no longer needed.

Once you have generated the secret you must store it securely. It must always be stored encrypted.

```php
use CitrusLab\Totp\Factory;

$user->totpSecret = encrypt(Factory::randomSecret());
$user->save();
```

Often, Base32 encoding is used with TOTP secrets, particularly when adding them to an authenticator app. If you need
your secret in Base32, _Totp_ provides a `Base32` codec class to do the conversion:

```php
use CitrusLab\Totp\Factory;

$user->totpSecret = encrypt(Factory::randomSecret()->base32());
$user->save();
```

Sometimes Base64 is also used, for which the `Secret::base64()` method is available.

### Minimising the secret's unencrypted availability

You should strive to minimise the time that the shared secret is unencrypted in RAM. Whenever you are using it, whether
to provision or to verify, you should only retrieve it just before you are ready to use it, you should discard it as
soon as you no longer need it, and you should ensure that the variable containing the secret is securely erased before
it is discarded. If you don't do this the unencrypted secret could remain "visible" in memory that is no longer used by
your app. The `scrubString()` function in the `\CitrusLab\Totp` namespace is available to achieve this - pass it the
string variable containing the secret and it will overwrite the string with random bytes.

All code in the _Totp_ library that is intended for use with TOTP secrets scrubs its data in this way to help prevent
unexpected visibility of TOTP secrets. You should `unset()` your instances of _Totp_ classes once you no longer need
them, and ensure that you don't keep unnecessary references.

### Notifying users

There are three common ways that users are provided with the details of their TOTP secret and most authenticator apps
support at least one of them - many support all three.

**1. Just the secret**

The first is simply providing them with the secret. Since the secret is a binary string, it will need to be converted to
some kind of text-safe format, and Base32 is usually used for this. This method of notifying users is only viable if the
standard TOTP setup is being used - that is 6-digit OTPs, SHA1 hashes, the Unix epoch as the reference time and 30
seconds as the time step. If you are using a custom TOTP setup, you will need to provide more information to your users,
and they will need to perform more steps to configure their authenticator app.

```php
use CitrusLab\Totp\Codecs\Base32;

$user->notify(Base32::encode(decrypt($user->totpSecret)));
```

**2. An `otpauth` URL**

The second method is to provide your users with a specially constructed URL that their authenticator app can read. The
URL format is [described here](https://github.com/google/google-authenticator/wiki/Key-Uri-Format). _Totp_ provides
a `UrlGenerator` class to create these URLs:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;
use CitrusLab\Totp\UrlGenerator;

$factory = new Factory()
$user->notify(UrlGenerator::from("MyWebApp")->for($user->username)->urlFor($factory->totp(new Secret(decrypt($user->totpSecret))));
```

By default, the UrlGenerator will insert as much information into the generated URL as is necessary to represent your
TOTP setup. So if you are using the SHA512 hash algorithm, the generated URL will contain the `algorithm` URL parameter
but if you're using the default SHA1 algorithm, the `algorithm` URL parameter will be omitted. The `UrlGenerator` class
provides a fluent interface to configure how it constructs the URLs (for example, you can force it to generate the
`algorithm` URL parameter regardless of whether you are using a non-default algorithm by chaining the `withAlgorithm()`
method before the `urlFor()` method).

This method of notifying supports all custom setups except those that use a non-standard reference time (since there is
no URL parameter for specifying it). Many TOTP-capable authenticator apps support URLs of this type, although you will
need to check the level of support in the app you are targeting for your users - for example _Google Authenticator_
supports URLs but does not recognise the `algorithm` parameter and always uses the SHA1 algorithm.

**3. A QR code**

The third method is to provide users with a QR code that their authenticator app can scan. This is effectively identical
to using the URL method above - the QR code is simply a representation of the generated URL.

_Totp_ does not (yet) have a QR code generator, but it should be simple to use an existing QR code generator along with
the `UrlGenerator` to create QR codes to send to your users.
[_bacon/bacon-qr-code_](https://packagist.org/packages/bacon/bacon-qr-code) is one such external library.

### Verifying successful provisioning

Once a user has been provisioned, you need to ask them for the OTP from their authenticator app to confirm that it
has been set up successfully. Once you've received the user's input, verification is simple:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;

use function CitrusLab\Totp\scrubString;

$factory = new Factory()
$isVerified = $factory->totp(new Secret(decrypt($user->totpSecret)))->verify($inputOtp);
scrubString($inputOtp);
```

To avoid problems arising when the user enters their OTP close to the end of a time step, you can choose to
accept a small number of previous passwords - typically just one - as well as the current password. Provide a `window`
argument to the `Totp::verify()` method, which identifies the maximum number of time steps the verification will go back
to check for a matching OTP.

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;

use function CitrusLab\Totp\scrubString;

$factory = new Factory()
$isVerified = $factory->totp(new Secret(decrypt($user->totpSecret)))->verify(password: $inputOtp, window: 1);
scrubString($inputOtp);
```

By default, `Totp::verify()` only accepts the current OTP. **It is very strongly recommended that you verify _at
most_ with a window of 1**.

### Batch-provisioning users

You can re-use an UrlGenerator instance to provision multiple users with TOTP and notify each of them with their own
unique URL.

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;
use CitrusLab\Totp\UrlGenerator;

$factory = new Factory()
$generator = UrlGenerator::from("CitrusLab");

foreach ($users as $user) {
   $user->totpSecret = encrypt(Factory::randomSecret());
   $user->save();
   $user->notify($generator->for($user->username)->urlFor($factory->totp(new Secret(decrypt($user->totpSecret)))));
}
```

## Authenticating

Authenticating users' TOTPs is mostly a simple case of asking the user for their current OTP and verifying it. This is
identical to verifying the initial setup of their TOTP app:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;

use function CitrusLab\Totp\scrubString;

$factory = new Factory()
$isVerified = $factory->totp(new Secret(decrypt($user->totpSecret)))->verify($inputOtp);
scrubString($inputOtp);
```

Or, with a window of verification:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;

use function CitrusLab\Totp\scrubString;

$factory = new Factory()
$isVerified = $factory->totp(new Secret(decrypt($user->totpSecret)))->verify(password: $inputOtp, window: 1);
scrubString($inputOtp);
```

If `Totp::verify()` returns `false`, the user has not provided the correct OTP and must not be authenticated with your
app; if it returns `true` the user has provided a valid OTP and can be authenticated.

### Ensuring OTPs are used only once

The RFC mandates that each generated OTP must be used only once to successfully authenticate - once an OTP has been used
to successfully authenticate, that OTP must not be used again.

One way to ensure each OTP is never reused is to record the TOTP counter after each successful authentication. The
counter is an incrementing integer that indicates how many time steps have passed since the reference time. By recording
the highest used counter value and refusing verification of any OTP generated at or before the corresponding time step
you can ensure that no OTP can be reused.

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;

use function CitrusLab\Totp\scrubString;

$factory = new Factory()
$totp = $factory->totp(new Secret(decrypt($user->totpSecret)));

if ($user->highestUsedTotpCounter < $totp->counter()) {
    if ($totp->verify($inputOtp)) {
       $user->highestUsedTotpCounter = $totp->counter();
       $user->save();
       // user is authenticated
    } else {
        // incorrect OTP
    }
} else {
    // OTP has already been used
}

// ensure the secret is shredded
scrubString($inputOtp);
unset($totp);
```

You can also use a verification window in the call to `Totp::verify()`, but don't forget to adjust the window to avoid
accepting a previously-used OTP:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Secret;

use function CitrusLab\Totp\scrubString;

$factory = new Factory()
$totp = $factory->totp(new Secret(decrypt($user->totpSecret)));
$window = min(1, $totp->counter() - $user->highestUsedTotpCounter - 1);

if (0 <= $window) {
    if ($totp->verify(password: $inputOtp, window: $window)) {
        ...
    }
}

// ensure the secret is shredded
scrubString($inputOtp);
unset($totp);
```

It is important that you ensure that **all routes to authentication that use the TOTP secret are protected against OTP
re-use** - for example if you have a mobile app and a web app, you must ensure that a OTP used to authenticate with the
web app cannot subsequently be used to authenticate using the mobile app.
[RFC 4226](https://www.ietf.org/rfc/rfc4226.txt) has a good discussion of the reasoning for this.

## Custom TOTP configurations

There are four things you can customise about your TOTP setup:

1. The hashing algorithm
2. The reference timestamp
3. The size of the time step
4. The number of digits in your OTPs

Customising your TOTP setup should be considered a one-time option. Once you have settled on a setup it is difficult
to change it (you'd need to re-provision all your users and they would all need to reconfigure their authenticator apps)
so it's usually best to choose your setup carefully before you begin.

Both the `Factory` constructor and the convenience methods `Factory::sixDigits()`, `Factory::eightDigits()` and
`Factory::integer()` accept arguments to customise all four aspects of TOTP. All these arguments use the defaults
specified in the TOTP RFC unless you explicitly provide a value, which means you can use PHP's named arguments to
customise only those aspects of your TOTP instances that are non-default.

### Hashing algorithms

TOTP supports three hashing algorithms - **SHA1**, **SHA256** and **SHA512**. The strongest is SHA512, while the default
specified in the RFC is SHA1 (for compatibility with HOTP). As noted above, you should check that the authenticator apps
that you are targeting for your users support the algorithm you are intending to use before customising it.

_Totp_ uses a named type for the hash algorithm to prevent use of invalid values. The type provides constants for the
supported algorithms, and you're strongly advised to use them when creating your HashAlgorithm instance.

To use SHA256 create your `Factory` instance like this:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\HashAlgorithm;

$factory = new Factory(hashAlgorithm: new HashAlgorithm(HashAlgorithm::Sha256Algorithm));
```

Similarly, to use SHA512:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\HashAlgorithm;

$factory = new Factory(hashAlgorithm: new HashAlgorithm(HashAlgorithm::Sha512Algorithm));
```

### Reference timestamp and time step

The counter that TOTP uses is the number of time steps that have elapsed since the reference time. By default, the
reference time is 00:00:00 01/01/1970 (AKA the Unix epoch, or the Unix timestamp `0`). The default time step size is 30
seconds. Unless you have a good reason to change them, these defaults are reasonable choices. If you do choose to
customise the time step, bear in mind that very small intervals will make it harder for users since they'll have less
time available to enter the correct OTP. Similarly, making the interval too large can also make it difficult for users
since you may effectively lock them out for a short period if they log off after only a short session.

_Totp_ uses a named type for the time step to prevent use of invalid values.

To use a time step of 60 seconds instead of 30 create your `Factory` instances like this:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\TimeStep;

$factory = new Factory(timeStep: new TimeStep(60));
```

You can customise the reference time using either Unix timestamps:

```php
use CitrusLab\Totp\Factory;

$factory = new Factory(referenceTime: 86400);
```

or `DateTime` objects:

```php
use CitrusLab\Totp\Factory;

$factory = new Factory(referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")));
```

Both of these examples create a TOTP with the reference time set to midnight on January 2nd 1970 UTC. You are strongly
encouraged to use the UTC timezone when creating `DateTime` objects to avoid any confusion. The TOTP algorithm works
with Unix timestamps that are always measured from 00:00:00, 01/01/9170 UTC.

You can customise both the time step and reference time:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\TimeStep;

$factory = new Factory(timeStep: new TimeStep(60), referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")));
```

And also the hash algorithm:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\TimeStep;

$factory = new Factory(
    timeStep: new TimeStep(60),
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: new HashAlgorithm(HashAlgorithm::Sha512Algorithm),
);
```

### Password digits

The number of digits in OTPs defaults to 6, but can range from 6 to 9 inclusive. There's technically no reason why
larger numbers of digits can't be used, but there is nothing to gain other than padding OTPs with 0s to the left.

The easiest way to create a `Factory` that produces `Totp` instances renderering 8-digit passwords is to use the
`Factory::eightDigits()` convenience method:

```php
use CitrusLab\Totp\Factory;

$factory = Factory::eightDigits();
```

You can, of course, still customise other aspects of your `Totp`:

```php
use CitrusLab\Totp\Factory;

$factory = Factory::eightDigits(
    timeStep: new TimeStep(60),
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: new HashAlgorithm(HashAlgorithm::Sha512Algorithm),
);
```

If you want to use a less common number of digits, use the `Totp::integer()` method. _Totp_ uses a named type for the
number of digits to prevent use of invalid values.

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Digits;

$factory = Factory::integer(new Digits(9));
```

And again, with more customisation:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Types\Digits;
use CitrusLab\Totp\Types\HashAlgorithm;
use CitrusLab\Totp\Types\TimeStep;

$factory = Factory::integer(
    digits: new Digits(9),
    timeStep: new TimeStep(60),
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: new HashAlgorithm(HashAlgorithm::Sha512Algorithm),
);
```

For control over passwords beyond just the number of digits they contain, you can provide the `renderer` argument to the
constructor. For example, to have your `Totp` instances produce 5-character OTPs that are compatible with the _Steam_
authenticator:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Renderers\Steam;

$factory = new Factory(renderer: new Steam());
```

And along with other customisations:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Renderers\Steam;
use CitrusLab\Totp\Types\Digits;
use CitrusLab\Totp\Types\HashAlgorithm;
use CitrusLab\Totp\Types\TimeStep;

$factory = new Factory(
    renderer: new Steam(),
    timeStep: new TimeStep(60),
    referenceTime: new DateTime("1970-01-02 00:00:00", new DateTimeZone("UTC")),
    hashAlgorithm: new HashAlgorithm(HashAlgorithm::Sha512Algorithm),
);
```

## Base32/Base64 secrets

As mentioned above, TOTP is commonly used with secrets that are encoded either as Base32 or Base64 text to make them
easy to enter into authenticator apps. If you have your secrets stored using one of these encodings (for example in a
text field in your database), they will need decoding (as well as decrypting) before being passed to a `Totp` instance.

You can either do this yourself using the provided codec classes `CitrusLab\Totp\Codecs\Base32` and/or
`CitrusLab\Totp\Codecs\Base64`:

```php
use CitrusLab\Totp\Factory;
use CitrusLab\Totp\Codecs\Base32;
use CitrusLab\Totp\Codecs\Base64;

$factory = new Factory();
$totp = $factory->totp(new Secret(Base32::decode(decrypt($user->totpSecret))));
$totp = $factory->totp(new Secret(Base64::decode(decrypt($user->totpSecret))));
```

Or you can use the convenience methods on the `Secret` class:

```php
use CitrusLab\Totp\Factory;

$factory = new Factory();
$totp = $factory->totp(Secret::fromBase32(decrypt($user->totpSecret)));
$totp = $factory->totp(Secret::fromBase64(decrypt($user->totpSecret)));
```

## RFCs
- H. Krawczyk, M. Bellare & R. Canetti, _[RFC2104: HMAC: Keyed-Hashing for Message Authentication](https://www.ietf.org/rfc/rfc2104.txt)_, https://www.ietf.org/rfc/rfc2104.txt, retrieved 17th April, 2022.
- D. M'Raihi, M. Bellare, F. Hoornaert, D. Naccache & O. Ranen, 2005, _[RFC4226: HOTP: An HMAC-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc4226.txt)_, https://www.ietf.org/rfc/rfc4226.txt, retrieved 17th April, 2022.
- D. M'Raihi, S. Machani, M. Pei & J. Rydell, 2011, _[RFC6238: TOTP: Time-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc6238.txt)_, https://www.ietf.org/rfc/rfc6238.txt, retrieved 17th April, 2022.
