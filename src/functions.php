<?php

if (!function_exists('segwit_addr_encode')) {
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
     * $addr = null;
     * if(segwit_addr_encode($data, $hrp, 0, $addr)) {
     *     echo $addr . PHP_EOL;
     * } else {
     *     echo "Failed to encode segwit address" . PHP_EOL;
     * }
     *
     * // P2TR ($witnessVersion = 1)
     * $addr = null;
     * if(segwit_addr_encode($data, $hrp, 1, $addr)) {
     *     echo $addr . PHP_EOL;
     * } else {
     *     echo "Failed to encode segwit address" . PHP_EOL;
     * }
     *
     * ```
     *
     * @param string $data The data string to encode.
     * @param string $hrp human readable part (prefix).
     * @param int $witVer The witness version valid version are 0 ... 16
     *                    inclusive
     * @param string|null $output [Output] The encoded output.
     * @return bool
     * @throws InvalidArgumentException
     */
    function segwit_addr_encode(
        string $data,
        string $hrp,
        int $witVer,
        ?string &$output
    ): bool {
        return \Bech32\Bech32::encodeSegWit($data, $hrp, $witVer, $output);
    }
}

if (!function_exists('segwit_addr_decode')) {
    /**
     * Decode a SegWit address
     *
     * @param string $input
     * @param string|null $output [Output] The decoded output (Binary string!).
     * @param int $witVer [Optional] [Output] The decode witness version.
     * @param string $hpr [Optional] [Output] The decoded human readable part
     * @param \Bech32\Bech32Encoding|null $enc [Optional] [Output] The decoded encoding type.
     * @return bool
     */
    function segwit_addr_decode(
        string $input,
        ?string &$output,
        int &$witVer = -1,
        string &$hpr = "",
        ?\Bech32\Bech32Encoding &$enc = null
    ): bool {
        return \Bech32\Bech32::decodeSegWit(
            $input,
            $output,
            $witVer,
            $hpr,
            $enc
        );
    }
}

if (!function_exists('bech32_encode')) {
    /**
     * Encode a Bech32 or Bech32m string
     *
     * @param array<int> $data The data to encode.
     * @param string $hrp human readable part (prefix).
     * @param \Bech32\Bech32Encoding $enc The encoding to use
     * @return string|null Returns the encoded data if successful, null otherwise
     */
    function bech32_encode(
        array $data,
        string $hrp,
        \Bech32\Bech32Encoding $enc
    ): ?string {
        return \Bech32\Bech32::encode($data, $hrp, $enc);
    }
}

if (!function_exists('bech32_decode')) {
    /**
     * Decode a Bech32 or Bech32m string
     *
     * @param string $input The data to decode.
     * @param string $hpr [Output] Outputs the human readable part.
     * @param \Bech32\Bech32Encoding $enc [Output] Outputs the encoding used.
     * @return array<int>|null Returns the decoded data if successful, null otherwise
     */
    function bech32_decode(
        string $input,
        string &$hpr = "",
        \Bech32\Bech32Encoding &$enc = null
    ): ?array {
        return \Bech32\Bech32::decode($input, $hpr, $enc);
    }
}
