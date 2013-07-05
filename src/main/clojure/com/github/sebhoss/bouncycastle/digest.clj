(ns com.github.sebhoss.bouncycastle.digest
  (:import (org.bouncycastle.crypto.digests MD2Digest
                                            MD4Digest
                                            MD5Digest
                                            SHA1Digest
                                            SHA224Digest
                                            SHA256Digest
                                            SHA384Digest
                                            SHA3Digest
                                            SHA512Digest)))

(defn- digest [digest input]
  (.update digest input 0 (alength input))
  (let [result (byte-array (.getDigestSize digest))]
      (.doFinal digest result 0)
      result))

(defn md2 [bytes]
  (digest (MD2Digest.) bytes))

(defn md4 [bytes]
  (digest (MD4Digest.) bytes))

(defn md5 [bytes]
  (digest (MD5Digest.) bytes))

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
