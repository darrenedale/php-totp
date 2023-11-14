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

namespace Equit\Totp\Contracts;

interface Totp
{
    /**
     * @return string The hash algorithm that is being used when computing the OTP.
     */
    public function hashAlgorithm(): string;

    /**
     * @return int The time step, in seconds, used when computing the OTP.
     */
    public function timeStep(): int;

    /**
     * @return int The reference unix timestamp (T0 in RFC6238-speak).
     */
    public function referenceTimestamp(): int;

    /**
     * @return int The current counter.
     */
    public function counter(): int;

    /**
     * @return string The current OTP.
     */
    public function password(): string;

    /**
     * Verify user input against the OTP.
     *
     * Verification can support matching against OTPs from the immediately preceding time steps using the $window
     * parameter. A $window of 0 verifies against only the current OTP; a $window of 1 will also accept the OTP from the
     * immediately preceding timestep, and so on. It is VERY strongly recommended that implementations support a maximum
     * window of 1 (meaning only the current and the immediately previous OTP will be accepted).
     *
     * @param string $password The password input by the user.
     * @param int $window A window of preceding time steps to accept.
     *
     * @return bool true if the provided password matches the OTP, false if not.
     */
    public function verify(string $password, int $window = 0): bool;
}
