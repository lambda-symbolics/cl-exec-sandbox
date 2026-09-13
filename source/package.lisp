(defpackage #:cl-exec-sandbox
  (:use #:cl)
  (:export
   #:sandbox-error
   #:sandbox-error-message
   #:sandbox-policy-error
   #:sandbox-unavailable
   #:sandbox-unavailable-capability
   #:sandbox-execution-error
   #:sandbox-execution-error-command
   #:filesystem-rule
   #:make-filesystem-rule
   #:filesystem-rule-kind
   #:filesystem-rule-path
   #:filesystem-rule-subpath
   #:filesystem-rule-access
   #:sandbox-policy
   #:make-sandbox-policy
   #:sandbox-policy-filesystem-kind
   #:sandbox-policy-filesystem-rules
   #:sandbox-policy-network
   #:sandbox-policy-workspace-roots
   #:sandbox-policy-glob-scan-maximum-depth
   #:sandbox-policy-mount-proc-p
   #:sandbox-policy-isolate-processes-p
   #:sandbox-policy-protected-metadata-names
   #:read-only-sandbox-policy
   #:workspace-write-sandbox-policy
   #:appcontainer-sandbox-policy
   #:unrestricted-sandbox-policy
   #:external-sandbox-policy
   #:sandbox-capabilities
   #:sandbox-supported-p
   #:sandbox-plan
   #:sandbox-plan-program
   #:sandbox-plan-arguments
   #:sandbox-plan-environment
   #:sandbox-plan-working-directory
   #:sandbox-plan-cleanup-paths
   #:sandbox-build-plan
   #:sandbox-plan-cleanup
   #:sandbox-result
   #:sandbox-result-exit-code
   #:sandbox-result-output
   #:sandbox-result-output-truncated-p
   #:sandbox-result-error-output
   #:sandbox-result-error-output-truncated-p
   #:sandbox-result-timed-out-p
   #:sandbox-result-real-seconds
   #:run-sandboxed))

(defpackage #:cl-exec-sandbox/tests
  (:use #:cl #:cl-exec-sandbox)
  (:export #:run-tests))
