;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.key-generator-test
  (:require [bouncycastle.key-generator :refer :all]
            [clojure.test :refer :all]))

(def- not-nil? (complement nil?))

(deftest generate-key-test
  (testing "with default algorithm parameters"
    (is (not-nil? (generate-key "AES"))))
  (testing "with given key-strength"
    (is (not-nil? (generate-key "AES" :strength 192))))
  (testing "with required standard algorithms"
    (is (not-nil? (generate-key "AES")))
    (is (not-nil? (generate-key "DES")))
    (is (not-nil? (generate-key "DESede")))
    (is (not-nil? (generate-key "HmacSHA1")))
    (is (not-nil? (generate-key "HmacSHA256"))))
  (testing "with extra algorithms provided by Bouncy Castle"
    (is (not-nil? (generate-key "ARC4")))
    (is (not-nil? (generate-key "Blowfish")))
    (is (not-nil? (generate-key "Camellia")))
    (is (not-nil? (generate-key "CAST5")))
    (is (not-nil? (generate-key "CAST6")))
    (is (not-nil? (generate-key "GOST28147")))
    (is (not-nil? (generate-key "Grainv1")))
    (is (not-nil? (generate-key "Grain128")))
    (is (not-nil? (generate-key "HC128")))
    (is (not-nil? (generate-key "HC256")))
    (is (not-nil? (generate-key "Noekeon")))
    (is (not-nil? (generate-key "RC2")))
    (is (not-nil? (generate-key "RC5")))
    (is (not-nil? (generate-key "RC6")))
    (is (not-nil? (generate-key "Rijndael")))
    (is (not-nil? (generate-key "Salsa20")))
    (is (not-nil? (generate-key "SEED")))
    (is (not-nil? (generate-key "Serpent")))
    (is (not-nil? (generate-key "Skipjack")))
    (is (not-nil? (generate-key "TEA")))
    (is (not-nil? (generate-key "Twofish")))
    (is (not-nil? (generate-key "VMPC")))
    (is (not-nil? (generate-key "XTEA")))))
