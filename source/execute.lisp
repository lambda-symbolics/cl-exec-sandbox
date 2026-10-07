(in-package #:cl-exec-sandbox)

;;;; -- Results --

(defclass sandbox-result ()
  ((status :initarg :status :initform ':exited :reader sandbox-result-status
           :documentation "Exited, timeout, cancelled, launch-failed, or interrupted.")
   (output-capture :initarg :output-capture :initform nil
                   :reader sandbox-result-output-capture
                   :documentation "Raw output capture metadata.")
   (error-capture :initarg :error-capture :initform nil
                  :reader sandbox-result-error-capture
                  :documentation "Raw error capture metadata, NIL for merged output.")
   (cancelled-p :initarg :cancelled-p :initform nil
                :reader sandbox-result-cancelled-p
                :documentation "Whether cancellation was requested.")
   (exit-code :initarg :exit-code :reader sandbox-result-exit-code
              :type (or null integer)
              :documentation "Process exit status, or NIL when launch failed.")
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

(defun execute--safe-delete (path)
  "Remove transient PATH, allowing only empty directories to be removed."
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
                :element-type '(unsigned-byte 8)
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

(defun execute--join-reader (thread capture)
  "Join THREAD with bounded grace; interrupt a pipe held open by descendants."
  (unless (ignore-errors (sb-thread:join-thread thread :timeout 0.5 :default nil))
    (when (sb-thread:thread-alive-p thread)
      (ignore-errors (sb-thread:terminate-thread thread))
      (ignore-errors (sb-thread:join-thread thread :timeout 0.5 :default nil))
      (unless (member (sandbox-capture-status capture) '(:limit :write-error))
        (setf (sandbox-capture-status capture) ':interrupted))))
  nil)

(defun execute--render-capture (result capture limit &key output-slot truncated-slot)
  "Render a legacy prefix without hiding capture failures from the callback."
  (when capture
    (handler-case
        (multiple-value-bind (text truncated-p) (capture--read-prefix capture limit)
          (setf (slot-value result output-slot) text
                (slot-value result truncated-slot)
                (or truncated-p (sandbox-capture-truncated-p capture))))
      (error ()
        (setf (slot-value result truncated-slot) t)))))

(defun execute--capture-result
    (started &key output-capture error-capture (status ':interrupted) exit-code)
  "Construct execution metadata shared by creation and final callbacks."
  (make-instance 'sandbox-result
                 :exit-code exit-code :status status
                 :output-capture output-capture :error-capture error-capture
                 :timed-out-p (eq status ':timeout)
                 :cancelled-p (eq status ':cancelled)
                 :output "" :output-truncated-p nil
                 :error-output "" :error-output-truncated-p nil
                 :real-seconds (/ (- (get-internal-real-time) started)
                                  (coerce internal-time-units-per-second 'double-float))))

(defun execute--run-plan
    (plan input timeout merge-output-p output-limit error-output-limit
     &key capture-directory retain-output-p (capture-byte-limit 67108864)
       cancel-function capture-created-function capture-function)
  "Run PLAN with bounded raw pipes and unwind-safe capture ownership."
  (let* ((started (get-internal-real-time))
         (output-capture nil)
         (error-capture nil)
         (process nil)
         (readers nil)
         (status ':interrupted)
         (exit-code nil)
         (launch-error nil)
         (result nil))
    (unwind-protect
         (progn
           (handler-case
               (progn
                 (sb-sys:without-interrupts
                   (setf output-capture
                         (capture--allocate capture-directory
                                            :retained-p (not (null (or retain-output-p capture-directory)))))
                   (unless merge-output-p
                     (setf error-capture
                           (capture--allocate capture-directory
                                              :retained-p (not (null (or retain-output-p capture-directory)))))))
                 (when capture-created-function
                   (funcall capture-created-function
                            (execute--capture-result started
                                                     :output-capture output-capture
                                                     :error-capture error-capture)))
                 (execute--launch-plan
                  plan input ':stream ':stream merge-output-p
                  (lambda (launched-process) (setf process launched-process))))
             (error (condition)
               (setf launch-error condition status ':launch-failed)))
           (when process
             ;; Publish each reader before interrupts can leave its stream unowned.
             (sb-sys:without-interrupts
               (push (cons (sb-thread:make-thread
                            (lambda ()
                              (capture--drain (uiop:process-info-output process)
                                              output-capture capture-byte-limit))
                            :name "sandbox output capture")
                           output-capture)
                     readers)
               (when error-capture
                 (push (cons (sb-thread:make-thread
                              (lambda ()
                                (capture--drain (uiop:process-info-error-output process)
                                                error-capture capture-byte-limit))
                              :name "sandbox error capture")
                             error-capture)
                       readers)))
             (unless launch-error
               (loop while (uiop:process-alive-p process)
                     do (cond
                          ((and cancel-function (funcall cancel-function))
                           (setf status ':cancelled)
                           (return))
                          ((and timeout
                                (>= (/ (- (get-internal-real-time) started)
                                       internal-time-units-per-second)
                                    timeout))
                           (setf status ':timeout)
                           (return)))
                        (sleep 0.01))
               (when (eq status ':interrupted) (setf status ':exited)))))
      ;; Defer repeated asynchronous cancellation until native ownership, files,
      ;; metadata callbacks and transient cleanup have all been discharged.
      (sb-sys:without-interrupts
        (when process
          (unless (eq status ':exited)
            (execute--terminate-process plan process))
          (setf exit-code (ignore-errors (uiop:wait-process process))))
        (dolist (reader readers)
          (execute--join-reader (first reader) (rest reader)))
        (when process
          (ignore-errors (close (uiop:process-info-output process)))
          (unless merge-output-p
            (ignore-errors (close (uiop:process-info-error-output process)))))
        (capture--finish output-capture status)
        (capture--finish error-capture status)
        (setf result (execute--capture-result started
                                             :output-capture output-capture
                                             :error-capture error-capture
                                             :status status :exit-code exit-code))
        (unwind-protect
             (progn
               (execute--render-capture result output-capture output-limit
                                        :output-slot 'output :truncated-slot 'output-truncated-p)
               (execute--render-capture result error-capture error-output-limit
                                        :output-slot 'error-output :truncated-slot 'error-output-truncated-p)
               (when capture-function (funcall capture-function result)))
          (unless (or retain-output-p capture-directory)
            (when output-capture
              (execute--safe-delete (sandbox-capture-path output-capture)))
            (when error-capture
              (execute--safe-delete (sandbox-capture-path error-capture)))))))
    (when launch-error
      (error 'sandbox-execution-error
             :message (format nil "Could not launch sandbox: ~A" launch-error)
             :command (cons (uiop:native-namestring (sandbox-plan-program plan))
                            (sandbox-plan-arguments plan))
             :result result))
    result))

(defun run-sandboxed
    (program arguments
     &key policy working-directory environment clear-environment-p input timeout
       merge-output-p (output-limit nil output-limit-provided-p)
       (error-output-limit nil error-output-limit-provided-p) capture-directory
       retain-output-p (capture-byte-limit 67108864) cancel-function
       capture-created-function capture-function)
  "Run PROGRAM with bounded raw capture. DIRECTORY or RETAIN-OUTPUT-P transfers
capture file ownership to the caller. CAPTURE-FUNCTION receives final metadata
on every unwind after launch setup, including interruptions and launch failure.
CAPTURE-BYTE-LIMIT is a finite per-stream disk maximum; excess bytes are drained.
CANCEL-FUNCTION is polled while the child runs. Legacy limits count characters.
CAPTURE-CREATED-FUNCTION receives initial incomplete metadata before launch;
an error in that callback prevents launch and invokes final CAPTURE-FUNCTION."
  (unless (or (null timeout) (and (realp timeout) (plusp timeout)))
    (error 'sandbox-policy-error
           :message "TIMEOUT must be NIL or a positive number of seconds."))
  (when (or retain-output-p capture-directory)
    (unless output-limit-provided-p (setf output-limit 0))
    (unless error-output-limit-provided-p (setf error-output-limit 0)))
  (execute--validate-output-limit output-limit "OUTPUT-LIMIT")
  (execute--validate-output-limit error-output-limit "ERROR-OUTPUT-LIMIT")
  (unless (and (integerp capture-byte-limit) (<= 0 capture-byte-limit))
    (error 'sandbox-policy-error
           :message "CAPTURE-BYTE-LIMIT must be a non-negative integer."))
  (when capture-directory
    (setf capture-directory (uiop:ensure-directory-pathname capture-directory))
    (unless (uiop:directory-exists-p capture-directory)
      (error 'sandbox-policy-error :message "CAPTURE-DIRECTORY must already exist.")))
  (let ((plan (sandbox-build-plan program arguments
                                  :policy policy :working-directory working-directory
                                  :environment environment
                                  :clear-environment-p clear-environment-p)))
    (unwind-protect
         (execute--run-plan plan input timeout merge-output-p output-limit error-output-limit
                            :capture-directory capture-directory
                            :retain-output-p retain-output-p
                            :capture-byte-limit capture-byte-limit
                            :cancel-function cancel-function
                            :capture-created-function capture-created-function
                            :capture-function capture-function)
      (sb-sys:without-interrupts
        (unwind-protect
             (sandbox-plan-cleanup plan)
          (dolist (path (reverse (sandbox-plan-cleanup-paths plan)))
            (execute--safe-delete path)))))))
