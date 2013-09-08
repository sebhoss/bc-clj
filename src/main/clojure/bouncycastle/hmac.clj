;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.hmac
  "Wrapper around the HMAC algorithm provided by Bouncy Castle.

   References:
     - https://en.wikipedia.org/wiki/Hash-based_message_authentication_code"
  (:require [bouncycastle.digest :as digest])
  (:import org.bouncycastle.crypto.macs.HMac
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.Digest))

(defn- calculate-hmac [^Digest digest ^bytes key ^bytes input]
  (let [parameter (KeyParameter. key)
        hmac (HMac. digest)]
    (.init hmac parameter)
    (.update hmac input 0 (alength input))
    (let [result (byte-array (.getMacSize hmac))]
        (.doFinal hmac result 0)
        result)))

(defmacro ^:private def-hmacs []
  `(do 
     ~@(for [digest digest/known-digests
            :let [name (symbol (digest/extract-digest-name digest))]]
        `(defn ~name [key# input#]
           (calculate-hmac (new ~digest) key# input#)))))
(def-hmacs)
