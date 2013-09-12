;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.hmac-test
  (:require [clojure.test :refer [deftest are]]
            [bouncycastle.hmac :refer :all]
            [bouncycastle.digest-test :as inputs]
            [bouncycastle.encoding :refer [hex]]))

(def zero (.getBytes "" "UTF8"))
(def simple (.getBytes "key" "UTF8"))
(def bc (.getBytes "The Legion of the Bouncy Castle" "UTF8"))

(deftest hmac-test
  (are [hmac key input expected] (= expected (hex (hmac key input)))
       gost3411   zero   inputs/zero       "447d47ab386a9572c5ec1a7886b9135ee619801f9eb4573fe86dd1db476d852a"
       gost3411   simple inputs/standard   "e06ac9388fa2107fa7bb49d6b29c28a09a2c0cde316cd349a12bb4b0d3497370"
       gost3411   bc     inputs/derivative "8b4d97f4fd90653fe12b653b8f7cbe3c900f067ba70e1b7619bb0ab44f80b492"

       md2        zero   inputs/zero       "6f6e031223b36cd2a997787a03d16bf5"
       md2        simple inputs/standard   "13758b9534bfb38d850457814613b0c1"
       md2        bc     inputs/derivative "34dafb9fac11ff3ec9f6dc1c898e06cc"

       md4        zero   inputs/zero       "c8d444e3153b538850e7850fa84bb247"
       md4        simple inputs/standard   "8d3366c440a9c65124ab0b5f4ca27338"
       md4        bc     inputs/derivative "bf28ec786c2599403dec013b3817a573"

       md5        zero   inputs/zero       "74e6f7298a9c2d168935f58c001bad88"
       md5        simple inputs/standard   "80070713463e7749b90c2dc24911e275"
       md5        bc     inputs/derivative "d0b4c05872eb91eadf8335907fd9484a"

       ripemd128  zero   inputs/zero       "6b114a86a890295b0d26f232a229974c"
       ripemd128  simple inputs/standard   "ea830b2f823e559e753aecfa22cf666c"
       ripemd128  bc     inputs/derivative "508ea46ec49a03c1094f66cbfef63104"

       ripemd160  zero   inputs/zero       "44d86b658a3e7cbc1a2010848b53e35c917720ca"
       ripemd160  simple inputs/standard   "50278a77d4d7670561ab72e867383aef6ce50b3e"
       ripemd160  bc     inputs/derivative "0ad645ba6672bf341034584ca933bf83128a6992"

       ripemd256  zero   inputs/zero       "965c203c6dc600e5b1bedf9186a1e6d0a3c6f6c8661fcc3fef4929a3bd8232bb"
       ripemd256  simple inputs/standard   "39f102599868d204bbf6165139f79eaa856a75cf92d785492907e2fee4168097"
       ripemd256  bc     inputs/derivative "1ec051dda52c00175d28c14df25513088701fa3be464794905360a1600c0bf42"

       ripemd320  zero   inputs/zero       "9e16b99babb1d49ee2e621f1e771892512ff3c2464f740119de03ddc9a563aa473e75bc26829aeee"
       ripemd320  simple inputs/standard   "dfca8756189fc556323fb344001a927c161f83a9d8f402d092c537346ae977113c4d02cca757a7ad"
       ripemd320  bc     inputs/derivative "df4aaa7395d1cf2a9f5fafe960289339cdc58f9f6724c77ab232c4994bea54acefdddd4ee7ae0827"

       sha1       zero   inputs/zero       "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
       sha1       simple inputs/standard   "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
       sha1       bc     inputs/derivative "2ffac478972fd4655506326cae1374011cf47541"

       sha224     zero   inputs/zero       "5ce14f72894662213e2748d2a6ba234b74263910cedde2f5a9271524"
       sha224     simple inputs/standard   "88ff8b54675d39b8f72322e65ff945c52d96379988ada25639747e69"
       sha224     bc     inputs/derivative "72f7ab9f04ccd6d304283a350e72f5a2d3eab6ade9e414b8a7dbced6"

       sha256     zero   inputs/zero       "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
       sha256     simple inputs/standard   "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
       sha256     bc     inputs/derivative "5df89c4704d3c0617b83dcda059a279c3940286225ff41baafa30686f4e9d051"

       sha384     zero   inputs/zero       "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc"
       sha384     simple inputs/standard   "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237"
       sha384     bc     inputs/derivative "4887d128d865e563ff396f42fce7a14f60a9a6f5d6e244e3884176e4f96d8f9561f525d7c1325eb97edccb5e0d84b4b0"

       sha512     zero   inputs/zero       "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47"
       sha512     simple inputs/standard   "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"
       sha512     bc     inputs/derivative "1a750540c278d4511641217ee7351dc0b1ee82618a36926c6f564bf7475c8a92620961051d53c507cfc777a0b83a73e6282757ff9fe930897717384b045ed420"

       sha3       zero   inputs/zero       "edc12d69fe7f69cb73847d39cfa2c3fb1437007978564a4465b38b0c67f56a9c48fb08c6"
       sha3       simple inputs/standard   "96118d267128683a8bc37eef9d8c6a9300e3567eadf2ceba1b9ef1f542a2c0c80ce71e89"
       sha3       bc     inputs/derivative "515f59c299ba2ebcc236d08641230449d879a244a1b26c8a95b2e6ef809fcb1ee8e9d5fc"

       tiger      zero   inputs/zero       "8ec5756ef2066562d2ab48a7f5a48ff029a537d3a2cb82a1"
       tiger      simple inputs/standard   "fba544227e1471d8d47dd9d68c5008d554c6de6072ca2e2a"
       tiger      bc     inputs/derivative "a59c2106bfc19a86b26113748a957c54d52241afaca009e7"

       whirlpool  zero   inputs/zero       "57d739903190550defa77309ff7b72406a927bbc54e8fcdc98e145fa4c36ce83a9cf1605ad01e0d1925f93ac1d12b985a26044e9fb1b9cce24301faa76eaab53"
       whirlpool  simple inputs/standard   "7f7192e3a155cb6a8171584ba146882f26821658112dfd2601272db013517a31e573637d146584596f86a884eb0decc9514dde000ecf2476dc5d436a92197527"
       whirlpool  bc     inputs/derivative "45aa9b35cf2dc286936d4ebb61e3139f15f35bf0c19115f029c55cb664438946caf4a95a15e4f1fccfe20f4390e85a61a17e6ceb03df3c3c9595c8600d9f6e84"))
