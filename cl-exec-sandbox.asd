(asdf:defsystem #:cl-exec-sandbox
  :description "Policy-driven external process sandboxing for Common Lisp."
  :author "Lukáš Hozda"
  :license "ISC"
  :version "0.1.0"
  :serial t
  :depends-on (#:sb-posix)
  :components ((:module "source"
                :serial t
                :components ((:file "package")
                             (:file "conditions")
                             (:file "policy")
                             (:file "paths")
                             (:file "rules")
                             (:file "plan")
                             (:file "posix")
                             (:file "linux")
                             (:file "macos")
                             (:file "windows")
                             (:file "backend")
                             (:file "execute"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:cl-exec-sandbox/tests))))

(asdf:defsystem #:cl-exec-sandbox/tests
  :description "Tests for cl-exec-sandbox."
  :depends-on (#:cl-exec-sandbox #:sb-bsd-sockets)
  :serial t
  :components ((:module "tests"
                :serial t
                :components ((:file "tests"))))
  :perform (asdf:test-op (operation component)
             (declare (ignore operation component))
             (uiop:symbol-call '#:cl-exec-sandbox/tests '#:run-tests)))

(asdf:defsystem #:cl-exec-sandbox/windows-tests
  :description "Native Windows AppContainer enforcement tests."
  :depends-on (#:cl-exec-sandbox #:sb-bsd-sockets)
  :components ((:file "tests/windows-tests"))
  :perform (asdf:test-op (operation component)
             (declare (ignore operation component))
             (uiop:symbol-call '#:cl-exec-sandbox/tests '#:run-windows-tests)))
