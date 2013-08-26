;
; This program is free software. It comes without any warranty, to
; the extent permitted by applicable law. You can redistribute it
; and/or modify it under the terms of the Do What The Fuck You Want
; To Public License, Version 2, as published by Sam Hocevar. See
; http://www.wtfpl.net/ for more details.
;

; Load project namespaces
(require '(com.github.sebhoss.bouncycastle [digest :as digest]
                                   [digest-test :as digest-test]))

; 'clojure.test', 'clojure.repl' and 'clojure.tools.namespace.repl' support
(require '[clojure.tools.namespace.repl :refer :all])
(require '[clojure.repl :refer :all])
(require '[clojure.test :refer :all])

; Call (rat) to run all tests, or (rat "math") to run only tests in that namespace
(defn rat
  "[R]uns-[A]ll-[T]ests inside the whole project or in a separate namespace.

   Examples:
     * (rat)          - Run all tests in all project namespaces
     * (rat \"digest\")   - Run all tests in the digest/-namespace"
  ([] (run-all-tests #"com.github.sebhoss.bouncycastle.*-test"))
  ([namespace] (run-all-tests
                 (re-pattern (format "com.github.sebhoss.bouncycastle.%s-test"
                                     namespace)))))
