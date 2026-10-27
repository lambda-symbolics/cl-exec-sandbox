(defpackage #:cl-exec-sandbox/tests
  (:documentation "Tests for cl-exec-sandbox.")
  (:use #:cl)
  (:import-from #:cl-exec-sandbox
                #:sandbox-policy-error
                #:sandbox-unavailable
                #:sandbox-unavailable-capability
                #:sandbox-execution-error
                #:sandbox-execution-error-result
                #:make-filesystem-rule
                #:make-sandbox-policy
                #:sandbox-policy-filesystem-rules
                #:sandbox-policy-network
                #:read-only-sandbox-policy
                #:workspace-write-sandbox-policy
                #:appcontainer-sandbox-policy
                #:unrestricted-sandbox-policy
                #:external-sandbox-policy
                #:sandbox-capabilities
                #:sandbox-result-exit-code
                #:sandbox-result-output
                #:sandbox-result-output-truncated-p
                #:sandbox-result-error-output
                #:sandbox-result-error-output-truncated-p
                #:sandbox-result-timed-out-p
                #:sandbox-result-real-seconds
                #:sandbox-result-output-capture
                #:sandbox-result-error-capture
                #:sandbox-result-cancelled-p
                #:sandbox-result-status
                #:sandbox-capture-path
                #:sandbox-capture-retained-p
                #:sandbox-capture-byte-count
                #:sandbox-capture-observed-byte-count
                #:sandbox-capture-complete-p
                #:sandbox-capture-truncated-p
                #:sandbox-capture-status
                #:sample-capture
                #:decode-capture-bytes
                #:run-sandboxed)
  (:export #:run-tests))
