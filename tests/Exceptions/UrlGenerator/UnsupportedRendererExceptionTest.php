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

namespace CitrusLab\TotpTests\Exceptions\UrlGenerator;

use CitrusLab\Totp\Contracts\Renderer;
use CitrusLab\Totp\Exceptions\TotpException;
use CitrusLab\Totp\Exceptions\UrlGenerator\UnsupportedRendererException;
use CitrusLab\Totp\Renderers\EightDigits;
use CitrusLab\Totp\Renderers\Integer;
use CitrusLab\Totp\Renderers\SixDigits;
use CitrusLab\Totp\Types\Digits;
use CitrusLab\TotpTests\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

#[CoversClass(UnsupportedRendererException::class)]
final class UnsupportedRendererExceptionTest extends TestCase
{
    /**
     * Create an anonymous unsupported Renderer instance.
     *
     * @return Renderer The generated renderer.
     */
    private static function createUnsupportedRenderer(): Renderer
    {
        return new class implements Renderer
        {
            public function name(): string
            {
                return "fizzbuzz renderer";
            }

            public function render(string $hmac): string
            {
                return "fizzbuzz";
            }
        };
    }

    /**
     * Data provider with arguments for the exception constructor for testConstructor1(). */
    public static function providerTestConstructor1(): iterable
    {
        $unsupportedRenderer = self::createUnsupportedRenderer();
        yield "renderer-only" => [$unsupportedRenderer,];
        yield "renderer-and-message" => [$unsupportedRenderer, "This is not a supported renderer.",];
        yield "renderer-message-and-code" => [$unsupportedRenderer, "This is not a supported renderer.", 12,];
        yield "renderer-message-code-and-previous" => [$unsupportedRenderer, "This is not a supported renderer.", 12, new TotpException("foo"),];
    }

    /** Ensure the constructor initialises the exception as expected. */
    #[DataProvider("providerTestConstructor1")]
    public function testConstructor1(Renderer $renderer, string $message = "", int $code = 0, ?Throwable $previous = null): void
    {
        $actual = new UnsupportedRendererException($renderer, $message, $code, $previous);
        self::assertSame($renderer, $actual->getRenderer(), "Unsupported Renderer retrieved from exception was not as expected.");
        self::assertEquals($message, $actual->getMessage(), "Message retrieved from exception was not as expected.");
        self::assertEquals($code, $actual->getCode(), "Error code retrieved from exception was not as expected.");
        self::assertSame($previous, $actual->getPrevious(), "Previous throwable retrieved from exception was not as expected.");
    }

    /** Data provider with renderers for testGetRenderer1(). */
    public static function providerTestGetRenderer1(): iterable
    {
        yield "integer-renderer" => [new Integer(new Digits(7)),];
        yield "six-digits-renderer" => [new SixDigits(),];
        yield "eight-digits-renderer" => [new EightDigits(),];
        yield "anonymous-renderer" => [self::createUnsupportedRenderer(),];
    }

    /** Ensure getRenderer() returns the expected renderer. */
    #[DataProvider("providerTestGetRenderer1")]
    public function testGetRenderer1(Renderer $renderer): void
    {
        $actual = new UnsupportedRendererException($renderer);
        self::assertSame($renderer, $actual->getRenderer(), "Unsupported renderer retrieved from exception was not as expected.");
    }

    /** Data provider with renderers and their FQ class names for testGetRendererClass1(). */
    public static function providerTestGetRendererClass1(): iterable
    {
        yield "integer-renderer" => [new Integer(new Digits(7)), Integer::class,];
        yield "six-digits-renderer" => [new SixDigits(), SixDigits::class,];
        yield "eight-digits-renderer" => [new EightDigits(), EightDigits::class,];

        $unsupportedRenderer = self::createUnsupportedRenderer();
        yield "anonymous-renderer" => [$unsupportedRenderer, $unsupportedRenderer::class,];
    }

    /** Ensure getRendererClass() returns the expected renderer class name. */
    #[DataProvider("providerTestGetRendererClass1")]
    public function testGetRendererClass1(Renderer $renderer, string $class): void
    {
        $actual = new UnsupportedRendererException($renderer);
        self::assertEquals($class, $actual->getRendererClass(), "Unsupported renderer class retrieved from exception was not as expected.");
    }
}
