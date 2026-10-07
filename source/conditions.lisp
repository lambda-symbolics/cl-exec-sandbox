(in-package #:cl-exec-sandbox)

(define-condition sandbox-error (error)
  ((message
    :initarg :message
    :reader sandbox-error-message
    :type string
    :documentation "A concise description of the sandbox failure."))
  (:report (lambda (condition stream)
             (write-string (sandbox-error-message condition) stream)))
  (:documentation "The base condition for sandbox policy and execution failures."))

(define-condition sandbox-policy-error (sandbox-error)
  ()
  (:documentation "A malformed, contradictory, or unsupported policy was supplied."))

(define-condition sandbox-unavailable (sandbox-error)
  ((capability
    :initarg :capability
    :reader sandbox-unavailable-capability
    :type keyword
    :documentation "The unavailable backend capability."))
  (:documentation "The host cannot enforce one required sandbox capability."))

(define-condition sandbox-execution-error (sandbox-error)
  ((command
    :initarg :command
    :reader sandbox-execution-error-command
    :type list
     :documentation "The command that could not be started or supervised.")
   (result :initarg :result :initform nil
           :reader sandbox-execution-error-result
           :documentation "Final capture metadata when execution had begun."))
  (:documentation "A sandboxed process could not be launched or supervised."))
