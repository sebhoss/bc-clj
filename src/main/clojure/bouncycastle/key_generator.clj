;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.key-generator
  "Wrapper around key-generators provided by Bouncy Castle."
  (:import javax.crypto.KeyGenerator
           java.security.KeyPairGenerator
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(defn- generate [create-generator initialize-strength initialize-random create-key
                 & {:keys [strength random]}]
  (let [generator (create-generator (BouncyCastleProvider.))]
    (cond
      (and strength random) (initialize-random generator)
      strength              (initialize-strength generator))
    (create-key generator)))

(defn generate-key [algorithm & {:keys [strength random]}]
  (generate #(KeyGenerator/getInstance algorithm %)
            #(.init % strength)
            #(.init % strength random)
            #(.generateKey %)
            :strength strength
            :random random))

(defn generate-keypair [algorithm & {:keys [strength random]}]
  (generate #(KeyPairGenerator/getInstance algorithm %)
            #(.initialize % strength)
            #(.initialize % strength random)
            #(.generateKeyPair %)
            :strength strength
            :random random))
