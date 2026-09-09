(in-package #:cl-exec-sandbox)

;;;; -- Process Group Supervision --

(defun posix--process-group-supported-p ()
  "Return true on supported POSIX hosts with process-group supervision."
  (not (null (intersection '(:linux :darwin :freebsd :netbsd :openbsd)
                           *features*))))

(defun posix--find-process-group-helper ()
  "Return the installed process-group launcher pathname, or NIL."
  (let* ((override (uiop:getenv "CL_EXEC_SANDBOX_PROCESS_GROUP_HELPER"))
         (candidate
           (if override
               (pathname override)
               (asdf:system-relative-pathname
                :cl-exec-sandbox
                #P"build/cl-exec-sandbox-process-group"))))
    (when (path--executable-file-p candidate)
      (truename candidate))))

(defun posix--process-group-plan
    (program arguments cwd environment clear-environment-p)
  "Return a direct launch plan whose command owns a fresh process group."
  (let ((helper (posix--find-process-group-helper)))
    (unless helper
      (error 'sandbox-unavailable
             :message "Full-access execution requires the cl-exec-sandbox process-group helper."
             :capability :process-group-supervision))
    (make-instance 'sandbox-plan
                   :program helper
                   :arguments (append (list "--" (uiop:native-namestring program))
                                      arguments)
                   :environment environment
                   :environment-provided-p (or (not (null environment))
                                               clear-environment-p)
                   :working-directory cwd
                   :cleanup-paths nil
                   :termination-scope :process-group)))

(defun posix--terminate-process-group (process)
  "Urgently terminate the process group led by PROCESS.

Windows has no process groups, so there only the launched process itself is
terminated."
  #-win32
  (let ((process-id (uiop:process-info-pid process)))
    (when process-id
      (sb-posix:kill (- process-id) sb-posix:sigkill)))
  #+win32
  (uiop:terminate-process process :urgent t)
  nil)
