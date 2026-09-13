(in-package #:cl-exec-sandbox)

;;;; -- Results --

(defclass sandbox-result ()
  ((exit-code
    :initarg :exit-code
    :reader sandbox-result-exit-code
    :type integer
    :documentation "The process exit status, or a signal-derived implementation status.")
   (output
    :initarg :output
    :reader sandbox-result-output
    :type string
    :documentation "Captured standard output.")
   (output-truncated-p
    :initarg :output-truncated-p
    :reader sandbox-result-output-truncated-p
    :type boolean
    :documentation "Whether standard output exceeded its capture limit.")
   (error-output
    :initarg :error-output
    :reader sandbox-result-error-output
    :type string
    :documentation "Captured standard error.")
   (error-output-truncated-p
    :initarg :error-output-truncated-p
    :reader sandbox-result-error-output-truncated-p
    :type boolean
    :documentation "Whether standard error exceeded its capture limit.")
   (timed-out-p
    :initarg :timed-out-p
    :reader sandbox-result-timed-out-p
    :type boolean
    :documentation "Whether supervision terminated the process after its deadline.")
   (real-seconds
    :initarg :real-seconds
    :reader sandbox-result-real-seconds
    :type real
    :documentation "Elapsed monotonic wall-clock seconds."))
  (:documentation "The captured outcome of one sandboxed command."))

(defun execute--validate-output-limit (limit name)
  "Require LIMIT named by NAME to be NIL or a supported character count."
  (unless (or (null limit)
              (and (integerp limit)
                   (<= 0 limit)
                   (< limit array-dimension-limit)))
    (error 'sandbox-policy-error
           :message (format nil
                            "~A must be NIL or a non-negative integer below ~D."
                            name array-dimension-limit)))
  limit)

(defun execute--read-file (path limit)
  "Return up to LIMIT characters from PATH and whether more were available."
  (cond
    ((not (probe-file path))
     (values "" nil))
    ((null limit)
     (values (uiop:read-file-string path) nil))
    (t
     (with-open-file (stream path :direction :input)
       (let* ((buffer (make-string limit))
              (count  (read-sequence buffer stream)))
         (values (if (= count limit)
                     buffer
                     (subseq buffer 0 count))
                 (not (eq (read-char stream nil :eof) :eof))))))))

(defun execute--safe-delete (path)
  "Remove transient PATH only when it is still an empty file or directory."
  (when (probe-file path)
    (handler-case
        (if (uiop:directory-pathname-p (probe-file path))
            (uiop:delete-empty-directory path)
            (delete-file path))
      (error ()
        nil)))
  nil)

(defun execute--environment-entry->cons (entry)
  "Convert one KEY=VALUE environment ENTRY to UIOP's portable cons form."
  (let ((separator (position #\= entry)))
    (unless separator
      (error 'sandbox-policy-error
             :message (format nil "Malformed environment entry: ~S" entry)))
    (cons (intern (string-upcase (subseq entry 0 separator)) :keyword)
          (subseq entry (1+ separator)))))

(defun execute--launch-plan
    (plan input output-path error-path merge-output-p ownership-function)
  "Launch PLAN and publish its process through OWNERSHIP-FUNCTION."
  (let ((arguments
          (list :input input
                :output output-path
                :error-output (if merge-output-p :output error-path)
                :directory (sandbox-plan-working-directory plan)
                :ignore-error-status t)))
    (when (sandbox-plan-environment-provided-p plan)
      (setf arguments
            (append arguments
                    (list :env
                          (mapcar #'execute--environment-entry->cons
                                  (sandbox-plan-environment plan))))))
    (flet ((launch ()
             (apply #'uiop:launch-program
                    (cons (uiop:native-namestring
                           (sandbox-plan-program plan))
                          (sandbox-plan-arguments plan))
                    arguments)))
      #+sbcl
      (sb-sys:without-interrupts
        (funcall ownership-function (launch)))
      #-sbcl
      (funcall ownership-function (launch)))))

(defun execute--terminate-process (plan process)
  "Urgently terminate and reap PLAN's native process scope."
  (when (ignore-errors (uiop:process-alive-p process))
    (ecase (sandbox-plan-termination-scope plan)
      (:process
       (ignore-errors (uiop:terminate-process process :urgent t)))
      (:process-group
       (ignore-errors (posix--terminate-process-group process)))))
  (ignore-errors (uiop:wait-process process))
  nil)

(defun execute--run-plan
    (plan input timeout merge-output-p output-limit error-output-limit)
  "Run PLAN with INPUT, TIMEOUT, and capture limits, returning a result."
  (uiop:with-temporary-file (:pathname output-path
                             :prefix "cl-exec-sandbox-output-")
    (uiop:with-temporary-file (:pathname error-path
                               :prefix "cl-exec-sandbox-error-")
      (let ((started (/ (get-internal-real-time)
                        (coerce internal-time-units-per-second 'double-float)))
            (process nil)
            (reaped-p nil)
            (timed-out-p nil))
        (unwind-protect
             (progn
               (handler-case
                   (execute--launch-plan
                    plan input output-path error-path merge-output-p
                    (lambda (launched-process)
                      (setf process launched-process)))
                 (error (condition)
                   (error 'sandbox-execution-error
                          :message
                          (format nil
                                  "Could not launch sandbox: ~A"
                                  condition)
                          :command
                          (cons (uiop:native-namestring
                                 (sandbox-plan-program plan))
                                (sandbox-plan-arguments plan)))))
               (loop while (uiop:process-alive-p process)
                     for elapsed = (- (/ (get-internal-real-time)
                                         (coerce internal-time-units-per-second
                                                 'double-float))
                                      started)
                     do (when (and timeout (>= elapsed timeout))
                          (setf timed-out-p t)
                          (execute--terminate-process plan process)
                          (return))
                        (sleep 0.01))
               (let ((exit-code (uiop:wait-process process))
                     (finished
                       (/ (get-internal-real-time)
                          (coerce internal-time-units-per-second 'double-float))))
                 (setf reaped-p t)
                 (multiple-value-bind (output output-truncated-p)
                     (execute--read-file output-path output-limit)
                   (multiple-value-bind (error-output error-output-truncated-p)
                       (execute--read-file error-path error-output-limit)
                     (make-instance
                      'sandbox-result
                      :exit-code exit-code
                      :output output
                      :output-truncated-p output-truncated-p
                      :error-output error-output
                      :error-output-truncated-p error-output-truncated-p
                      :timed-out-p timed-out-p
                      :real-seconds (- finished started))))))
          (when (and process (not reaped-p))
            (execute--terminate-process plan process)))))))

(defun run-sandboxed
    (program arguments
     &key
       policy
       working-directory
       environment
       clear-environment-p
       input
       timeout
       merge-output-p
       output-limit
       error-output-limit)
  "Run PROGRAM and ARGUMENTS under POLICY and return a captured SANDBOX-RESULT."
  (unless (or (null timeout) (and (realp timeout) (plusp timeout)))
    (error 'sandbox-policy-error
           :message "TIMEOUT must be NIL or a positive number of seconds."))
  (execute--validate-output-limit output-limit "OUTPUT-LIMIT")
  (execute--validate-output-limit error-output-limit "ERROR-OUTPUT-LIMIT")
  (let ((plan (sandbox-build-plan program arguments
                                  :policy policy
                                  :working-directory working-directory
                                  :environment environment
                                  :clear-environment-p clear-environment-p)))
    (unwind-protect
         (execute--run-plan plan input timeout merge-output-p
                            output-limit error-output-limit)
      (unwind-protect
           (sandbox-plan-cleanup plan)
        (dolist (path (reverse (sandbox-plan-cleanup-paths plan)))
          (execute--safe-delete path))))))
