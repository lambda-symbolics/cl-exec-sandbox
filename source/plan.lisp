(in-package #:cl-exec-sandbox)

;;;; -- Launch Plan --

(defclass sandbox-plan ()
  ((program
    :initarg :program
    :reader sandbox-plan-program
    :type pathname
    :documentation "The host program that starts the planned command.")
   (arguments
    :initarg :arguments
    :reader sandbox-plan-arguments
    :type list
    :documentation "Arguments passed to PROGRAM.")
   (environment
   :initarg :environment
    :reader sandbox-plan-environment
    :type list
    :documentation "Environment entries passed to PROGRAM as KEY=VALUE strings.")
   (environment-provided-p
    :initarg :environment-provided-p
    :reader sandbox-plan-environment-provided-p
    :type boolean
    :documentation "Whether execution should replace rather than inherit the host environment.")
   (working-directory
    :initarg :working-directory
    :reader sandbox-plan-working-directory
    :type pathname
    :documentation "The host working directory used for a direct launch.")
    (cleanup-paths
     :initarg :cleanup-paths
     :reader sandbox-plan-cleanup-paths
     :type list
     :documentation "Transient host paths removed after execution when still safe.")
    (termination-scope
     :initarg :termination-scope
     :initform :process
     :reader sandbox-plan-termination-scope
     :type (member :process :process-group)
     :documentation "The native process scope terminated on timeout or cancellation."))
  (:documentation "A fully validated native launch plan and its cleanup obligations."))

(defgeneric sandbox-plan-cleanup (plan)
  (:documentation "Release backend-owned resources after PLAN's process tree has stopped."))

(defmethod sandbox-plan-cleanup ((plan sandbox-plan))
  (declare (ignore plan))
  nil)
