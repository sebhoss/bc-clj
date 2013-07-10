;   This program is free software. It comes without any warranty, to the extent permitted by applicable law.
;   You can redistribute it and/or modify it under the terms of the Do What The Fuck You Want To Public
;   License, Version 2, as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.

(require '[com.github.sebhoss.bootstrap.repl :refer :all])

; Load project namespaces
(load-namespaces #".*?bc-clj")

; 'clojure.test', 'clojure.repl' and 'clojure.tools.namespace.repl' support
(load-helpers)


(defn rat
  "[R]uns-[A]ll-[T]ests inside the whole project or in a separate namespace.

   Examples:
     * (rat)          - Run all tests in all project namespaces
     * (rat \"digest\")   - Run all tests in the digest/-namespace"
  ([] (run-all-tests #"com.github.sebhoss.bouncycastle.*-test"))
  ([namespace] (run-all-tests
                 (re-pattern (format "com.github.sebhoss.bouncycastle.%s-test"
                                     namespace)))))
