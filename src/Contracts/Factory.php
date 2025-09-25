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

namespace Equit\Totp\Contracts;

use Equit\Totp\Exceptions\InvalidTimeStepException;
use Equit\Totp\Totp;
use Equit\Totp\Types\Secret;

/** Contract for factories that produce TOTP generators. */
interface Factory
{
    /**
     * Produce a TOTP calculator for a given set of parameters.
     *
     * @param Secret $secret The secret to use to generate passwords.
     * @return Totp
     * @throws InvalidTimeStepException
     */
    public function totp(Secret $secret): Totp;
}
