<?php

namespace Test;

use Bech32\Bech32;
use Bech32\Bech32Encoding;
use PHPUnit\Framework\TestCase;

/**
 * @link https://github.com/sipa/bech32/blob/master/ref/c/tests.c
 */
final class Bech32Test extends TestCase
{
    /**
     * @dataProvider dataValidChecksumBech32
     */
    public function testValidChecksumBech32(string $value): void
    {
        $hpr = '';
        $this->assertNotNull($result = Bech32::decode($value, $hpr, $enc));
        $this->assertEquals($enc, Bech32Encoding::BECH32);
        $this->assertNotEmpty($hpr);

        $this->assertNotNull(
            /** @phpstan-ignore-next-line */
            $result2 = Bech32::encode($result, $hpr, Bech32Encoding::BECH32)
        );

        $this->assertEqualsIgnoringCase($value, $result2);
    }

    /**
     * @dataProvider dataValidChecksumBech32m
     */
    public function testValidChecksumBech32m(string $value): void
    {
        $hpr = '';
        $this->assertNotNull($result = Bech32::decode($value, $hpr, $enc));
        $this->assertEquals($enc, Bech32Encoding::BECH32M);
        $this->assertNotEmpty($hpr);

        $this->assertNotNull(
            /** @phpstan-ignore-next-line */
            $result2 = Bech32::encode($result, $hpr, Bech32Encoding::BECH32M)
        );

        $this->assertEqualsIgnoringCase($value, $result2);
    }

    /**
     * @dataProvider dataInvalidChecksumBech32
     */
    public function testInvalidChecksumBech32(string $value): void
    {
        $hpr = '';
        $this->assertEmpty($result = Bech32::decode($value, $hpr, $enc));
        $this->assertNotEquals($enc, Bech32Encoding::BECH32);
    }

    /**
     * @dataProvider dataInvalidChecksumBech32m
     */
    public function testInvalidChecksumBech32m(string $value): void
    {
        $hpr = '';
        $this->assertEmpty($result = Bech32::decode($value, $hpr, $enc));
        $this->assertNotEquals($enc, Bech32Encoding::BECH32M);
    }

    /**
     * @dataProvider dataInvalidAddresses
     */
    public function testInvalidAddresses(string $value): void
    {
        $output = null;
        $this->assertFalse(Bech32::decodeSegWit($value, $output));
    }

    /**
     * @dataProvider dataInvalidAddressesEnc
     */
    public function testInvalidAddressesEnc(string $hrp, int $version, int $pl): void
    {
        $output = null;
        $this->expectException(\InvalidArgumentException::class);
        $this->assertFalse(
            Bech32::encodeSegWit('', $hrp, $version, $output)
        );
    }

    /**
     * @dataProvider dataValidAddresses
     * @param string $address
     * @param int $keyLen
     * @param array<int> $key
     * @return void
     */
    public function testValidAddressesc(string $address, int $keyLen, array $key): void
    {
        $output = null;
        $witnessVersion = -1;
        $hpr = "";
        $this->assertTrue(
            Bech32::decodeSegWit($address, $output, $witnessVersion, $hpr, $enc)
        );

        $spubkey = array_pad([], $keyLen, "\x0");
        $spubkey[0] = $witnessVersion ? (0x50 + $witnessVersion) : $witnessVersion;
        $spubkey[1] = strlen($output);
        for ($i = 0; $i < $spubkey[1]; $i++) {
            $spubkey[$i + 2] = ord($output[$i]);
        }
        $this->assertSame($key, $spubkey);
    }

    /**
     * @return array<int, array<int, array<int, int>|int|string>>.
     */
    public function dataValidAddresses(): array
    {
        return [
            [
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                22, [
                    0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            ],
            [
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                34, [
                    0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
                    0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
                    0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
                    0x62
                ]
            ],
            [
                "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
                42, [
                    0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                    0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
                    0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            ],
            [
                "BC1SW50QGDZ25J",
                4, [
                   0x60, 0x02, 0x75, 0x1e
                ]
            ],
            [
                "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
                18, [
                    0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
                ]
            ],
            [
                "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                34, [
                    0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
                    0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
                    0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
                    0x33
                ]
            ],
            [
                "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
                34, [
                    0x51, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
                    0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
                    0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
                    0x33
                ]
            ],
            [
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                34, [
                    0x51, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55,
                    0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb,
                    0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
                    0x98
                ]
            ],
        ];
    }

    /**
     * @return array<int, array<int, int|string>>
     */
    public function dataInvalidAddressesEnc(): array
    {
        return [
            ["BC", 0, 20],
            ["bc", 0, 21],
            ["bc", 17, 32],
            ["bc", 1, 1],
            ["bc", 16, 41]
        ];
    }

    /**
     * @return array<int, array<int, string>>
     */
    public function dataInvalidAddresses(): array
    {
        return [
            ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd"],
            ["tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf"],
            ["BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL"],
            ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh"],
            ["tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47"],
            ["bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4"],
            ["BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R"],
            ["bc1pw5dgrnzv"],
            ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav"],
            ["tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq"],
            ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf"],
            ["tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j"],
            ["bc1gmk9yu"],
        ];
    }

    /**
     * @return array<int, array<int, string>>
     */
    public function dataInvalidChecksumBech32m(): array
    {
        return [
            [" 1xj0phk"],
            ["\x7F\"1g6xzxy"],
            ["\x80\"1vctc34"],
            ["an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4"],
            ["qyrz8wqd2c9m"],
            ["1qyrz8wqd2c9m"],
            ["y1b0jsk6g"],
            ["lt1igcx5c0"],
            ["in1muywd"],
            ["mm1crxm3i"],
            ["au1s5cgom"],
            ["M1VUXWEZ"],
            ["16plkw9"],
            ["1p2gdwpf"],
        ];
    }

    /**
     * @return array<int, array<int, string>>
     */
    public function dataInvalidChecksumBech32(): array
    {
        return [
            [" 1nwldj5"],
            ["\x7f\"1axkwrx"],
            ["\x80\"1eym55h"],
            ["an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"],
            ["pzry9x0s0muk"],
            ["1pzry9x0s0muk"],
            ["x1b4n0q5v"],
            ["li1dgmt3"],
            ["de1lg7wt\xff"],
            ["A1G7SGD8"],
            ["10a06t8"],
            ["1qzzfhee"],
        ];
    }


    /**
     * @return array<int, array<int, string>>
     */
    public function dataValidChecksumBech32m(): array
    {
        return [
            ["A1LQFN3A"],
            ["a1lqfn3a"],
            ["an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6"],
            ["abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"],
            ["11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8"],
            ["split1checkupstagehandshakeupstreamerranterredcaperredlc445v"],
            ["?1v759aa"],
        ];
    }

    /**
     * @return array<int, array<int, string>>
     */
    public function dataValidChecksumBech32(): array
    {
        return [
            ["A12UEL5L"],
            ["a12uel5l"],
            ["an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs"],
            ["abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"],
            ["11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"],
            ["split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"],
            ["?1ezyfcl"],
        ];
    }
}
