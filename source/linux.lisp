(in-package #:cl-exec-sandbox)

;;;; -- Bubblewrap Discovery --

(defun linux--find-bwrap ()
  "Return the configured or trusted system Bubblewrap pathname."
  (let ((override (uiop:getenv "CL_EXEC_SANDBOX_BWRAP")))
    (or (when (and override
                   (uiop:absolute-pathname-p (pathname override))
                   (path--executable-file-p (pathname override)))
          (truename override))
        (loop for candidate in '(#P"/usr/bin/bwrap" #P"/bin/bwrap")
              when (path--executable-file-p candidate)
                return (truename candidate)))))

(defun linux--find-helper ()
  "Return the installed internal Linux helper pathname, or NIL."
  (let* ((override (uiop:getenv "CL_EXEC_SANDBOX_HELPER"))
         (candidate
           (if override
               (pathname override)
               (asdf:system-relative-pathname
                :cl-exec-sandbox
                #P"build/cl-exec-sandbox-helper"))))
    (when (path--executable-file-p candidate)
      (truename candidate))))


;;;; -- Bubblewrap Plan --

(defun linux--append-target-parent-arguments (arguments path)
  "Append --dir operations ensuring PATH's parent components exist in a minimal root."
  (let ((components (butlast (path--components path)))
        (current    ""))
    (dolist (component components arguments)
      (setf current (concatenate 'string current "/" component))
      (setf arguments (append arguments (list "--dir" current))))))

(defun linux--root-access (rules)
  "Return the final access of an exact root rule in RULES, or NIL."
  (let ((matches
          (remove-if-not
           (lambda (rule)
             (string= (uiop:native-namestring
                       (resolved-filesystem-rule-path rule))
                      "/"))
           rules)))
    (when matches
      (resolved-filesystem-rule-access (first (last matches))))))

(defun linux--existing-path-p (path)
  "Return true when PATH exists without requiring directory syntax agreement."
  (not (null (probe-file path))))

(defun linux--writable-descendants (rule rules)
  "Return writable RULES strictly below denied directory RULE."
  (let ((path (resolved-filesystem-rule-path rule)))
    (remove-if-not
     (lambda (candidate)
       (let ((candidate-path (resolved-filesystem-rule-path candidate)))
         (and (eq (resolved-filesystem-rule-access candidate) :write)
              (not (equal candidate-path path))
              (path--under-p candidate-path path))))
     rules)))

(defun linux--append-descendant-parent-arguments (arguments descendant root)
  "Create missing parents of DESCENDANT beneath a freshly masked ROOT."
  (let ((directories nil)
        (current     (if (uiop:directory-pathname-p descendant)
                         descendant
                         (uiop:pathname-parent-directory-pathname descendant))))
    (loop while (and current
                     (path--under-p current root)
                     (not (equal current root)))
          do (push current directories)
             (setf current (uiop:pathname-parent-directory-pathname current)))
    (dolist (directory directories arguments)
      (setf arguments
            (append arguments
                    (list "--dir" (uiop:native-namestring directory)))))))

(defun linux--append-directory-mask (arguments target permissions descendants)
  "Append a read-only empty directory mask at TARGET with PERMISSIONS."
  (setf arguments
        (append arguments (list "--perms" permissions "--tmpfs" target)))
  (dolist (descendant descendants)
    (setf arguments
          (linux--append-descendant-parent-arguments
           arguments
           (resolved-filesystem-rule-path descendant)
           (pathname target))))
  (append arguments (list "--remount-ro" target)))

(defun linux--append-rule-arguments
    (arguments rule minimal-root-p deny-file-mask rules)
  "Append RULE's effective mount operation to ARGUMENTS."
  (let* ((path   (resolved-filesystem-rule-path rule))
         (target (uiop:native-namestring path))
         (source (and (probe-file path) target)))
    (when minimal-root-p
      (setf arguments (linux--append-target-parent-arguments arguments path)))
    (case (resolved-filesystem-rule-access rule)
      (:read
       (when source
         (setf arguments (append arguments (list "--ro-bind" source target)))))
      (:write
       (when source
         (setf arguments (append arguments (list "--bind" source target)))))
      (:deny
       (if (or (not (probe-file path))
               (uiop:directory-pathname-p (probe-file path)))
           (let ((descendants (linux--writable-descendants rule rules)))
             (setf arguments
                   (linux--append-directory-mask
                    arguments target
                    (if descendants "111" "000")
                    descendants)))
           (setf arguments
                 (append arguments
                         (list "--ro-bind"
                               (uiop:native-namestring deny-file-mask)
                               target)))))
      (otherwise
       (error 'sandbox-policy-error
              :message "Unknown resolved filesystem access.")))
    (when (and (eq (resolved-filesystem-rule-origin rule) :protected-metadata)
               (not (probe-file path)))
      (setf arguments
            (linux--append-directory-mask arguments target "555" nil)))
    arguments))

(defun linux--temporary-mask-file ()
  "Create and return a mode-000 host file suitable for denying one sandbox path."
  (loop
    for candidate =
      (merge-pathnames
       (format nil "cl-exec-sandbox-mask-~36R-~36R"
               (get-universal-time) (random most-positive-fixnum))
       (uiop:temporary-directory))
    unless (probe-file candidate)
      do (with-open-file (stream candidate
                                  :direction         :output
                                  :if-does-not-exist :create
                                  :if-exists         :error)
           (file-position stream 0))
         (multiple-value-bind (output error-output status)
             (uiop:run-program (list "chmod" "000"
                                     (uiop:native-namestring candidate))
                               :output              :string
                               :error-output        :string
                               :ignore-error-status t)
           (declare (ignore output error-output))
           (unless (zerop status)
             (delete-file candidate)
             (error 'sandbox-unavailable
                    :message    "Could not create a deny-path mask file."
                    :capability :filesystem-deny)))
         (return candidate)))

(defun linux--base-arguments (policy cwd root-access environment clear-environment-p)
  "Return namespace, base filesystem, environment, and working-directory arguments."
  (let ((arguments (list "--die-with-parent" "--new-session")))
    (when (sandbox-policy-isolate-processes-p policy)
      (setf arguments
            (append arguments
                    (list "--unshare-user" "--unshare-pid"
                          "--unshare-ipc" "--unshare-uts"))))
    (unless (eq (sandbox-policy-network policy) :enabled)
      (setf arguments (append arguments (list "--unshare-net"))))
    (if root-access
        (setf arguments
              (append arguments
                      (list (if (eq root-access :write) "--bind" "--ro-bind")
                            "/" "/")))
        (progn
          (setf arguments (append arguments (list "--tmpfs" "/")))
          (dolist (root +linux-platform-read-roots+)
            (when (probe-file root)
              (setf arguments
                    (linux--append-target-parent-arguments arguments root)
                    arguments
                    (append arguments
                            (list "--ro-bind"
                                  (uiop:native-namestring root)
                                  (uiop:native-namestring root))))))))
    (setf arguments (append arguments (list "--dev" "/dev")))
    (when (sandbox-policy-mount-proc-p policy)
      (setf arguments (append arguments (list "--proc" "/proc"))))
    (when clear-environment-p
      (setf arguments (append arguments (list "--clearenv"))))
    (dolist (entry environment)
      (let ((separator (position #\= entry)))
        (unless separator
          (error 'sandbox-policy-error
                 :message (format nil "Malformed environment entry: ~S" entry)))
        (setf arguments
              (append arguments
                      (list "--setenv"
                            (subseq entry 0 separator)
                            (subseq entry (1+ separator)))))))
    (append arguments (list "--chdir" (uiop:native-namestring cwd)))))

(defun linux--bubblewrap-plan
    (program arguments policy cwd environment clear-environment-p)
  "Return a bubblewrap launch plan for PROGRAM and ARGUMENTS under POLICY."
  (let ((bwrap  (linux--find-bwrap))
        (helper (unless (eq (sandbox-policy-network policy) :enabled)
                  (linux--find-helper))))
    (unless bwrap
      (error 'sandbox-unavailable
             :message    "A restricted Linux sandbox requires bubblewrap on trusted PATH."
             :capability :bubblewrap))
    (when (and (not (eq (sandbox-policy-network policy) :enabled))
               (not helper))
      (error 'sandbox-unavailable
             :message    "Restricted networking requires the cl-exec-sandbox Linux helper."
             :capability :seccomp-helper))
    (let* ((rules          (rules--resolve-rules policy cwd))
           (root-access    (linux--root-access rules))
           (minimal-root-p (null root-access))
           (deny-file-mask
             (when (find-if
                    (lambda (rule)
                      (let ((path (resolved-filesystem-rule-path rule)))
                        (and (eq (resolved-filesystem-rule-access rule) :deny)
                             (probe-file path)
                             (not (uiop:directory-pathname-p
                                   (probe-file path))))))
                    rules)
               (linux--temporary-mask-file)))
           (bwrap-arguments
             (linux--base-arguments policy cwd root-access
                                    environment clear-environment-p)))
      (when (and helper minimal-root-p)
        (setf bwrap-arguments
              (linux--append-target-parent-arguments bwrap-arguments helper)
              bwrap-arguments
              (append bwrap-arguments
                      (list "--ro-bind"
                            (uiop:native-namestring helper)
                            (uiop:native-namestring helper)))))
      (dolist (rule rules)
        (unless (string= (uiop:native-namestring
                          (resolved-filesystem-rule-path rule))
                         "/")
          (setf bwrap-arguments
                (linux--append-rule-arguments
                 bwrap-arguments
                 rule
                 minimal-root-p
                 deny-file-mask
                 rules))))
      (let* ((network (sandbox-policy-network policy))
             (inner-command
               (if helper
                   (append (list (uiop:native-namestring helper)
                                 "inner"
                                 (string-downcase (symbol-name network))
                                 "--"
                                 (uiop:native-namestring program))
                           arguments)
                   (cons (uiop:native-namestring program) arguments)))
             (command (append bwrap-arguments (list "--") inner-command))
             (synthetic-targets
               (loop for rule in rules
                     for path = (resolved-filesystem-rule-path rule)
                     when (and (not (probe-file path))
                               (or (eq (resolved-filesystem-rule-access rule) :deny)
                                   (eq (resolved-filesystem-rule-origin rule)
                                       :protected-metadata)))
                       collect path))
             (cleanup-paths
               (append synthetic-targets
                       (when deny-file-mask (list deny-file-mask)))))
        (if (eq network :proxy-only)
            (make-instance 'sandbox-plan
                           :program                helper
                           :arguments              (append (list "proxy-outer" "--"
                                                                (uiop:native-namestring bwrap))
                                                           command)
                           :environment            environment
                           :environment-provided-p (or (not (null environment))
                                                       clear-environment-p)
                           :working-directory      cwd
                           :cleanup-paths          cleanup-paths)
            (make-instance 'sandbox-plan
                           :program                bwrap
                           :arguments              command
                           :environment            nil
                           :environment-provided-p nil
                           :working-directory      cwd
                           :cleanup-paths          cleanup-paths))))))
