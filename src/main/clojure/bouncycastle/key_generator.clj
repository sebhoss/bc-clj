;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.key-generator
  "Wrapper around key-generators provided by Bouncy Castle."
  (:import javax.crypto.KeyGenerator
           (java.security KeyPairGenerator Provider SecureRandom)
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(defn- generate [create-generator initialize-strength initialize-random create-key
                 & {:keys [strength random]}]
  (let [generator (create-generator (BouncyCastleProvider.))]
    (cond
      (and strength random) (initialize-random generator)
      strength              (initialize-strength generator))
    (create-key generator)))

(defn generate-key [^String algorithm & {:keys [^int strength ^SecureRandom random]}]
  (generate #(KeyGenerator/getInstance algorithm ^Provider %)
            #(.init ^KeyGenerator % strength)
            #(.init ^KeyGenerator % strength random)
            #(.generateKey ^KeyGenerator %)
            :strength strength
            :random random))

(defn generate-keypair [^String algorithm & {:keys [^int strength ^SecureRandom random]}]
  (generate #(KeyPairGenerator/getInstance algorithm ^Provider %)
            #(.initialize ^KeyPairGenerator % strength)
            #(.initialize ^KeyPairGenerator % strength random)
            #(.generateKeyPair ^KeyPairGenerator %)
            :strength strength
            :random random))
