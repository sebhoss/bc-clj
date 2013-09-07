;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.digest-test
  (:require [bouncycastle.digest :refer :all]
            [clojure.test :refer [deftest are]]))

(def zero (.getBytes "" "UTF8"))
(def standard (.getBytes "The quick brown fox jumps over the lazy dog" "UTF8"))
(def derivative (.getBytes "The quick brown fox jumps over the lazy cog" "UTF8"))

(defn- hexify [bytes]
  (apply str (map #(format "%02x" %) bytes)))

(deftest digest-test
  (are [digest input expected] (= expected (hexify (digest input)))
       gost       zero       "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"
       gost       standard   "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76"
       gost       derivative "a93124f5bf2c6d83c3bbf722bc55569310245ca5957541f4dbd7dfaf8137e6f2"

       md2        zero       "8350e5a3e24c153df2275c9f80692773"
       md2        standard   "03d85a0d629d2c442e987525319fc471"
       md2        derivative "6b890c9292668cdbbfda00a4ebf31f05"

       md4        zero       "31d6cfe0d16ae931b73c59d7e0c089c0"
       md4        standard   "1bee69a46ba811185c194762abaeae90"
       md4        derivative "b86e130ce7028da59e672d56ad0113df"

       md5        zero       "d41d8cd98f00b204e9800998ecf8427e"
       md5        standard   "9e107d9d372bb6826bd81d3542a419d6"
       md5        derivative "1055d3e698d289f2af8663725127bd4b"

       ripemd128  zero       "cdf26213a150dc3ecb610f18f6b38b46"
       ripemd128  standard   "3fa9b57f053c053fbe2735b2380db596"
       ripemd128  derivative "3807aaaec58fe336733fa55ed13259d9"

       ripemd160  zero       "9c1185a5c5e9fc54612808977ee8f548b2258d31"
       ripemd160  standard   "37f332f68db77bd9d7edd4969571ad671cf9dd3b"
       ripemd160  derivative "132072df690933835eb8b6ad0b77e7b6f14acad7"

       ripemd256  zero       "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"
       ripemd256  standard   "c3b0c2f764ac6d576a6c430fb61a6f2255b4fa833e094b1ba8c1e29b6353036f"
       ripemd256  derivative "b44055d843dea5bcd2151e52b1a0dbc5e8e34493e5fe2f000c0e71f73c3ddcae"

       ripemd320  zero       "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8"
       ripemd320  standard   "e7660e67549435c62141e51c9ab1dcc3b1ee9f65c0b3e561ae8f58c5dba3d21997781cd1cc6fbc34"
       ripemd320  derivative "393e0df728c4ce3d79e7dcfd357d5c26f5c6d64c6d652dc53b6547b214ea9183e4f61c477ebf5cb0"

       sha1       zero       "da39a3ee5e6b4b0d3255bfef95601890afd80709"
       sha1       standard   "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
       sha1       derivative "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"

       sha224     zero       "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
       sha224     standard   "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"
       sha224     derivative "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b"

       sha256     zero       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
       sha256     standard   "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
       sha256     derivative "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be"

       sha384     zero       "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
       sha384     standard   "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"
       sha384     derivative "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b"

       sha512     zero       "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
       sha512     standard   "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
       sha512     derivative "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045"

       sha3       zero       "6753e3380c09e385d0339eb6b050a68f66cfd60a73476e6fd6adeb72f5edd7c6f04a5d01"
       sha3       standard   "0bbe6afae0d7e89054085c1cc47b1689772c89a41796891e197d1ca1b76f288154933ded"
       sha3       derivative "343db38a98e769e4b16faa7b333129a6a2db0b8fd5d5fb00632d09c923b7e07d903a1235"

       tiger      zero       "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"
       tiger      standard   "6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075"
       tiger      derivative "a8f04b0f7201a0d728101c9d26525b31764a3493fcd8458f"

       whirlpool  zero       "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
       whirlpool  standard   "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35"
       whirlpool  derivative "dce81fc695cfea3d7e1446509238daf89f24cc61896f2d265927daa70f2108f8902f0dfd68be085d5abb9fcd2e482c1dc24f2fabf81f40b73495cad44d7360d3"))
