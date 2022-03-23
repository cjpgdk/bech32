<?php

declare(strict_types=1);

namespace Bech32;

use InvalidArgumentException;

/**
 * Bech32 encoder / decoder.
 *
 * @link https://github.com/sipa/bech32/ Based on Pieter Wuille's bech32.
 */
class Bech32
{
    protected const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    protected const CHARSET_REV = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
         1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
         1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    ];

    /**
     * Decode a SegWit address
     *
     * @param string $input
     * @param string|null $output The decoded output (Binary string!).
     * @param int $witnessVersion The decode witness version.
     * @param string $hpr The decoded human readable part
     * @param Bech32Encoding $enc The decoded encoding type.
     * @return bool
     */
    public static function decodeSegWit(
        string $input,
        ?string &$output,
        int &$witnessVersion = -1,
        string &$hpr = "",
        Bech32Encoding &$enc = null
    ): bool {
        $data = Bech32::decode($input, $hpr, $enc);

        if ($enc === Bech32Encoding::NONE || !$data) {
            return false;
        }

        $dataLen = count($data);
        if ($dataLen > 65) {
            return false;
        }

        $witnessVersion = array_shift($data);
        if (
            ($witnessVersion > 16) ||
            ($witnessVersion == 0 && $enc !== Bech32Encoding::BECH32) ||
            ($witnessVersion > 0 && $enc !== Bech32Encoding::BECH32M)
        ) {
            return false;
        }

        $output = Bech32::convertBitsToString($data, 8, 5, false);
        if (!$output) {
            return false;
        }

        $outputLen = strlen($output);
        if ($outputLen < 2 || $outputLen > 40) {
            return false;
        }
        return true;
    }

    /**
     * Decode a Bech32 or Bech32m string
     *
     * @param string $input The data to decode.
     * @param string $hpr Outputs the human readable part.
     * @param Bech32Encoding $enc Outputs the encoding used.
     * @return array<int>|null
     */
    public static function decode(string $input, string &$hpr = "", Bech32Encoding &$enc = null): ?array
    {
        $inputLen = strlen($input);
        if ($inputLen < 8 || $inputLen > 90) {
            $enc = Bech32Encoding::NONE;
            return null;
        }

        $dataLen = 0;
        while ($dataLen < $inputLen && $input[($inputLen - 1) - $dataLen] != '1') {
            ++$dataLen;
        }

        $hrpLen = $inputLen - (1 + $dataLen);
        if (1 + $dataLen >= $inputLen || $dataLen < 6) {
            $enc = Bech32Encoding::NONE;
            return null;
        }

        $chk = 1;
        $haveLower = $haveUpper = false;
        $dataLen -= 6;
        for ($i = 0; $i < $hrpLen; ++$i) {
            $ch = ord($input[$i]);
            if ($ch < 33 || $ch > 126) {
                $enc = Bech32Encoding::NONE;
                return null;
            }

            // ch >= 'a' && ch <= 'z'
            if ($ch >= 97 && $ch <= 122) {
                $haveLower = true;

            // ch >= 'A' && ch <= 'Z'
            } elseif ($ch >= 65 && $ch <= 90) {
                $haveUpper = true;
                // ch = (ch - 'A') + 'a';
                $ch = ($ch - 65) + 97;
            }
            $hpr[$i] = chr($ch);
            $chk = static::polymodStep($chk) ^ ($ch >> 5);
        }

        $chk = static::polymodStep($chk);
        for ($i = 0; $i < $hrpLen; ++$i) {
            $chk = static::polymodStep($chk) ^ (ord($input[$i]) & 0x1f);
        }
        $result = array_pad([], ($inputLen - 7 - $hrpLen), 0);

        while (++$i < $inputLen) {
            $ch = ord($input[$i]);
            $v = ($ch & 0x80) ? -1 : static::CHARSET_REV[$ch];

            if ($ch >= 97 && $ch <= 122) {
                $haveLower = true;
            }
            if ($ch >= 65 && $ch <= 90) {
                $haveUpper = true;
            }
            if ($v == -1) {
                $enc = Bech32Encoding::NONE;
                return null;
            }
            $chk = static::polymodStep($chk) ^ $v;
            if ($i + 6 < $inputLen) {
                $result[$i - (1 + $hrpLen)] = $v;
            }
        }


        if ($haveLower && $haveUpper) {
            $enc = Bech32Encoding::NONE;
            return $result;
        }

        if ($chk == static::finalConstant(Bech32Encoding::BECH32)) {
            $enc = Bech32Encoding::BECH32;
        } elseif ($chk == static::finalConstant(Bech32Encoding::BECH32M)) {
            $enc = Bech32Encoding::BECH32M;
        } else {
            $enc = Bech32Encoding::NONE;
        }
        return $result;
    }

    /**
     * Encode a SegWit address.
     *
     * ```php
     *
     * // the public key to use.
     * $publicKey = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
     *
     * // perform a hash160 ripemd160(sha256($publicKey)).
     * // note the return binary flag, that is important.
     * $data = hash('ripemd160', hash('sha256', hex2bin($publicKey), true), true);
     *
     * $hrp = "bc";
     *
     * // P2WPKH / P2WSH ($witnessVersion = 0)
     * echo Bech32::encodeSegWit($data, $hrp, 0).PHP_EOL;
     *
     * // P2TR ($witnessVersion = 1)
     * echo Bech32::encodeSegWit($data, $hrp, 1).PHP_EOL;
     *
     * ```
     *
     * @param string $data The data string to encode.
     * @param string $hrp human readable part (prefix).
     * @param int $witnessVersion The witness version valid version are
     *                            0 ... 16 inclusive
     * @param string|null $output The encoded output.
     * @return bool
     * @throws InvalidArgumentException
     */
    public static function encodeSegWit(
        string $data,
        string $hrp,
        int $witnessVersion,
        ?string &$output
    ): bool {
        // check witness verison.
        if ($witnessVersion < 0 ||  $witnessVersion > 16) {
            throw new InvalidArgumentException(
                "Invalid witness version [{$witnessVersion}], "
                . "accepted values are 0 ... 16 inclusive"
            );
        }

        $dataLen = strlen($data);

        // $witnessVersion == 0  length check.
        if ($witnessVersion == 0 && $dataLen != 20 && $dataLen != 32) {
            throw new InvalidArgumentException(
                "Invalid data for version 0, expected 20 or 32 characters"
                . " but got {$dataLen}"
            );
        }

        // min/max length check.
        if ($dataLen < 2 || $dataLen > 40) {
            throw new InvalidArgumentException(
                "Invalid data, expected minimum 2 and maximum 40 characters"
                . " but got {$dataLen}"
            );
        }

        $enc = Bech32Encoding::BECH32;
        if ($witnessVersion > 0) {
            $enc = Bech32Encoding::BECH32M;
        }

        $converted = Bech32::convertBitsFromString($data, 5, 8, true);
        if (!$converted) {
            return false;
        }

        $output = Bech32::encode(
            array_merge([$witnessVersion], $converted),
            $hrp,
            $enc
        );
        return !empty($output);
    }

    /**
     * Encode a Bech32 or Bech32m string
     *
     * @param array<int> $data The data to encode.
     * @param string $hrp human readable part (prefix).
     * @param Bech32Encoding $enc The encoding to use
     * @return string|null Returns the encoded data if successful, null otherwise
     */
    public static function encode(array $data, string $hrp, Bech32Encoding $enc): ?string
    {
        $len = count($data);
        $chk = 1;
        for ($i = 0; $i < strlen($hrp); $i++) {
            $ch = ord($hrp[$i]);
            if ($ch < 33 || $ch > 126) {
                return null;
            }
            // ch >= 'A' && ch <= 'Z'
            if ($ch >= 65 && $ch <= 90) {
                return null;
            }
            $chk = static::polymodStep($chk) ^ ($ch >> 5);
        }

        if (($i + 7 + $len) > 90) {
            return null;
        }

        $output = $hrp;
        $chk = static::polymodStep($chk);
        for ($i = 0; $i < strlen($hrp); $i++) {
            $chk = static::polymodStep($chk) ^ (ord($hrp[$i]) & 0x1f);
        }

        $output .= "1";
        for ($i = 0; $i < $len; $i++) {
            if ($data[$i] >> 5) {
                return null;
            }

            $chk = static::polymodStep($chk) ^ $data[$i];
            $output .= static::CHARSET[$data[$i]];
        }

        for ($i = 0; $i < 6; $i++) {
            $chk = static::polymodStep($chk);
        }
        $chk ^= static::finalConstant($enc);
        for ($i = 0; $i < 6; $i++) {
            $output .= static::CHARSET[($chk >> ((5 - $i) * 5)) & 0x1f];
        }
        return $output;
    }

    /**
     * The reverse of 'convertBitsFromString'.
     *
     * ```php
     *
     * $data = [... some ... character ... (numeric) ... array ...];
     *
     * //--
     *
     * $string = Bech32::convertBitsFromString($data, 5, 8, false);
     *
     * // ^Above is this same as this.^
     *
     * $decoded = Bech32::convertBits($data, 5, 8, false);
     * $string = pack('C*', ...$decoded);
     *
     * ```
     *
     * @param array<int> $data
     * @param int $outBits
     * @param int $inBits
     * @param bool $pad
     * @return string|null
     */
    public static function convertBitsToString(array $data, int $outBits, int $inBits, bool $pad): ?string
    {
        $decoded = Bech32::convertBits($data, $outBits, $inBits, $pad);
        if (!$decoded) {
            return null;
        }
        return pack('C*', ...$decoded);
    }

    /**
     * Same as 'convertBits' but takes a normal string as input, converts it to
     * a character (numeric) array, and runs it thru 'convertBits'.
     *
     * ```php
     *
     * $data = "The super nisse string that needs encoding";
     * $data = array_values(unpack('C*', $data));
     * $data = Bech32::convertBits($data, 5, 8, true);
     *
     * // ^Above is this same as this.^
     *
     * $data = Bech32::convertBitsFromString(
     *     "The super nisse string that needs encoding", 5, 8, true
     * );
     *
     * // and encode it.
     *
     * $enc  = Bech32Encoding::BECH32;
     * $hrp  = "sample";
     *
     * echo Bech32::encode($data, $hrp, $enc).PHP_EOL;
     *
     * ```
     *
     * @param string $data
     * @param int $outBits
     * @param int $inBits
     * @param bool $pad
     * @return array<int>|null
     */
    public static function convertBitsFromString(string $data, int $outBits, int $inBits, bool $pad): ?array
    {
        $unpack = unpack('C*', $data);
        if (!$unpack) {
            return null;
        }
        return Bech32::convertBits(
            array_values($unpack),
            $outBits,
            $inBits,
            $pad
        );
    }

    /**
     * @param array<int> $data
     * @param int $outBits
     * @param int $inBits
     * @param bool $pad
     * @return array<int>|null return null on failure
     */
    public static function convertBits(array $data, int $outBits, int $inBits, bool $pad): ?array
    {
        $val = 0;
        $bits = 0;
        $maxV = (1 << $outBits) - 1;
        $result = [];

        for ($i = 0; $i < count($data); ++$i) {
            $val = ($val << $inBits) | $data[$i];
            $bits += $inBits;

            while ($bits >= $outBits) {
                $bits -= $outBits;
                $result[] = (($val >> $bits) & $maxV);
            }
        }

        if ($pad) {
            if ($bits > 0) {
                $result[] = (($val << ($outBits - $bits)) & $maxV);
            }
        } elseif ((($val << ($outBits - $bits)) & $maxV) || $bits >= $inBits) {
            return null;
        }

        return $result;
    }

    /**
     * @param Bech32Encoding $enc
     * @return int
     * @throws InvalidArgumentException
     */
    protected static function finalConstant(Bech32Encoding $enc): int
    {
        if ($enc === Bech32Encoding::BECH32) {
             return 1;
        }
        if ($enc === Bech32Encoding::BECH32M) {
            return 0x2bc830a3;
        }
        throw new InvalidArgumentException(
            "\$enc must be one of Bech32Encoding::BECH32, Bech32Encoding::BECH32M"
        );
    }

    /**
     * @param int $pre
     * @return int
     */
    protected static function polymodStep(int $pre): int
    {
        $b = $pre >> 25;
        return (($pre & 0x1FFFFFF) << 5) ^
            (-(($b >> 0) & 1) & 0x3b6a57b2) ^
            (-(($b >> 1) & 1) & 0x26508e6d) ^
            (-(($b >> 2) & 1) & 0x1ea119fa) ^
            (-(($b >> 3) & 1) & 0x3d4233dd) ^
            (-(($b >> 4) & 1) & 0x2a1462b3);
    }
}
