;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.digest
  "Wrapper around digest algorithms provided by Bouncy Castle."
  (:import (org.bouncycastle.crypto.digests GOST3411Digest
                                            MD2Digest
                                            MD4Digest
                                            MD5Digest
                                            RIPEMD128Digest
                                            RIPEMD160Digest
                                            RIPEMD256Digest
                                            RIPEMD320Digest
                                            SHA1Digest
                                            SHA224Digest
                                            SHA256Digest
                                            SHA384Digest
                                            SHA3Digest
                                            SHA512Digest
                                            TigerDigest
                                            WhirlpoolDigest)
           org.bouncycastle.crypto.Digest))

(defn digest [^Digest digestToUse ^bytes input]
  (.update digestToUse input 0 (alength input))
  (let [result (byte-array (.getDigestSize digestToUse))]
      (.doFinal digestToUse result 0)
      result))

(def ^:private digests [GOST3411Digest
                        MD2Digest MD4Digest MD5Digest
                        RIPEMD128Digest RIPEMD160Digest RIPEMD256Digest RIPEMD320Digest
                        SHA1Digest SHA224Digest SHA256Digest SHA384Digest SHA3Digest SHA512Digest
                        TigerDigest
                        WhirlpoolDigest])

(defn- extract-name [class]
  (let [simple-name (.getSimpleName class)
        algo-name (subs simple-name 0 (- (count simple-name)
                                         (count "Digest")))]
    (clojure.string/lower-case algo-name)))

(defmacro ^:private def-digests []
  `(do 
     ~@(for [algorithm digests
            :let [name (symbol (extract-name algorithm))]]
        `(defn ~name [input#]
           (digest (new ~algorithm) input#)))))
(def-digests)
