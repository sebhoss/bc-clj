;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.key-generator
  "Wrapper around key-generators provided by Bouncy Castle."
  (:import javax.crypto.KeyGenerator
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(defn generate-key [algorithm & {:keys [strength]}]
  (let [generator (KeyGenerator/getInstance algorithm (BouncyCastleProvider.))]
    (if strength
      (-> generator (.init strength)))
    (-> generator (.generateKey))))
