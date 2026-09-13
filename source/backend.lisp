(in-package #:cl-exec-sandbox)

;;;; -- Backend Capability Discovery --

(defun sandbox-capabilities ()
  "Return a portable plist describing the current host sandbox backend."
  (let* ((linux-p  (not (null (member :linux *features*))))
         (macos-p  (not (null (member :darwin *features*))))
         (bwrap    (and linux-p (linux--find-bwrap)))
         (seatbelt (and macos-p (macos--find-sandbox-exec)))
         (appcontainer (and (member :win32 *features*) (windows--find-helper)))
         (rg       (and (or linux-p macos-p) (rules--find-rg)))
         (helper   (and linux-p (linux--find-helper)))
         (backend  (cond
                     (bwrap    :bubblewrap)
                     (seatbelt :seatbelt)
                     (appcontainer :appcontainer)
                     (t        nil))))
    (list :platform (cond
                      (linux-p :linux)
                      (macos-p :macos)
                      ((member :win32 *features*) :windows)
                      (t :unknown))
          :backend backend
          :available-p (not (null backend))
          :filesystem-read-write-deny (not (null backend))
          :filesystem-read-only-host (and (not (null backend)) (not appcontainer))
          :explicit-filesystem-scopes (not (null backend))
          :filesystem-deny-globs (and (not (null backend)) (not (null rg)))
          :nested-overrides (not (null backend))
          :process-namespaces (not (null bwrap))
          :network-enabled (not (null (or bwrap seatbelt)))
          :network-isolated (or (and (not (null bwrap)) (not (null helper)))
                                (not (null seatbelt)) (not (null appcontainer)))
          :network-proxy-only (and (not (null bwrap)) (not (null helper)))
          :seccomp (not (null helper)))))

(defun sandbox-supported-p (&optional (capability :available-p))
  "Return true when the host reports CAPABILITY in SANDBOX-CAPABILITIES."
  (not (null (getf (sandbox-capabilities) capability))))


;;;; -- Plan Dispatch --

(defun backend--direct-plan
    (program arguments cwd environment clear-environment-p)
  "Return a direct plan with process-group supervision on supported hosts."
  (if (posix--process-group-supported-p)
      (posix--process-group-plan program arguments cwd environment clear-environment-p)
      (make-instance 'sandbox-plan
                     :program program
                     :arguments arguments
                     :environment environment
                     :environment-provided-p (or (not (null environment))
                                                 clear-environment-p)
                     :working-directory cwd
                     :cleanup-paths nil)))

(defun sandbox-build-plan
    (program arguments
     &key policy working-directory environment clear-environment-p)
  "Build a validated native launch plan for PROGRAM and ARGUMENTS."
  (unless (typep policy 'sandbox-policy)
    (error 'sandbox-policy-error
           :message "SANDBOX-BUILD-PLAN requires a SANDBOX-POLICY."))
  (unless (and (listp arguments) (every #'stringp arguments))
    (error 'sandbox-policy-error
           :message "Command arguments must be a list of strings."))
  (let* ((cwd (policy--absolute-directory
               (or working-directory (uiop:getcwd))
               "The command working directory"))
         (program-path
           (let ((pathname (pathname program)))
             (if (uiop:absolute-pathname-p pathname)
                 pathname
                 (or (loop for directory in (path--directories)
                           for candidate = (find-if #'path--executable-file-p
                                                    (path--executable-candidates
                                                     pathname directory))
                           when candidate
                             return (truename candidate))
                     (error 'sandbox-execution-error
                            :message (format nil "Could not find executable ~A." program)
                            :command (cons program arguments)))))))
    (cond
      ((eq (sandbox-policy-filesystem-kind policy) :external)
       (backend--direct-plan program-path arguments cwd environment
                             clear-environment-p))
      ((and (eq (sandbox-policy-filesystem-kind policy) :unrestricted)
            (eq (sandbox-policy-network policy) :enabled))
       (backend--direct-plan program-path arguments cwd environment
                             clear-environment-p))
      ((member :linux *features*)
       (linux--bubblewrap-plan program-path arguments policy cwd
                               environment clear-environment-p))
      ((member :darwin *features*)
       (macos--seatbelt-plan program-path arguments policy cwd
                             environment clear-environment-p))
      ((member :win32 *features*)
       (windows--appcontainer-plan program-path arguments policy cwd
                                  environment clear-environment-p))
      (t
       (error 'sandbox-unavailable
              :message "No sandbox backend is available for this operating system."
              :capability :platform-backend)))))
