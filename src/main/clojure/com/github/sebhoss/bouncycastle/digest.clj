(ns com.github.sebhoss.bouncycastle.digest
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

(defn- digest [digest input]
  (.update digest input 0 (alength input))
  (let [result (byte-array (.getDigestSize digest))]
      (.doFinal digest result 0)
      result))

(defn gost3411 [bytes]
  (digest (GOST3411Digest.) bytes))

(defn md2 [bytes]
  (digest (MD2Digest.) bytes))

(defn md4 [bytes]
  (digest (MD4Digest.) bytes))

(defn md5 [bytes]
  (digest (MD5Digest.) bytes))

(defn ripemd128 [bytes]
  (digest (RIPEMD128Digest.) bytes))

(defn ripemd160 [bytes]
  (digest (RIPEMD160Digest.) bytes))

(defn ripemd256 [bytes]
  (digest (RIPEMD256Digest.) bytes))

(defn ripemd320 [bytes]
  (digest (RIPEMD320Digest.) bytes))

(defn sha1 [bytes]
  (digest (SHA1Digest.) bytes))

(defn sha224 [bytes]
  (digest (SHA224Digest.) bytes))

(defn sha256 [bytes]
  (digest (SHA256Digest.) bytes))

(defn sha384 [bytes]
  (digest (SHA384Digest.) bytes))

(defn sha3 [bytes]
  (digest (SHA3Digest.) bytes))

(defn sha512 [bytes]
  (digest (SHA512Digest.) bytes))

(defn tiger [bytes]
  (digest (TigerDigest.) bytes))

(defn whirlpool [bytes]
  (digest (WhirlpoolDigest.) bytes))
