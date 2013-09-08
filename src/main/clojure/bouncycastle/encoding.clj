;
; Copyright © 2013 Sebastian Hoß <mail@shoss.de>
; This work is free. You can redistribute it and/or modify it under the
; terms of the Do What The Fuck You Want To Public License, Version 2,
; as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
;

(ns bouncycastle.encoding
  "Wrapper around encoders provided by Bouncy Castle."
  (:import (org.bouncycastle.util.encoders Base64 Hex)))

(defn base64 [bytes]
  (Base64/toBase64String bytes))

(defn hex [bytes]
  (Hex/toHexString bytes))
