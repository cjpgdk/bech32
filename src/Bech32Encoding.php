<?php
// @codingStandardsIgnoreFile

declare(strict_types=1);

namespace Bech32;

enum Bech32Encoding: int
{
    case NONE = 0;

    /**
     * Bech32 encoding as defined in BIP173
     * @link https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
     */
    case BECH32 = 1;

    /**
     * Bech32m encoding as defined in BIP350
     * @link https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
     */
    case BECH32M = 2;
}
