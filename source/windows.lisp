(in-package #:cl-exec-sandbox)

;;;; Native AppContainer launch plans

(defun windows--find-helper ()
  "Return the explicitly configured or locally built Windows helper."
  (let* ((override (uiop:getenv "CL_EXEC_SANDBOX_WINDOWS_HELPER"))
         (candidate
           (if (and override (plusp (length override)))
               (uiop:parse-native-namestring override)
               (merge-pathnames "build/cl-exec-sandbox-windows.exe"
                                (asdf:system-source-directory :cl-exec-sandbox)))))
    (when (and (uiop:absolute-pathname-p candidate)
               (path--executable-file-p candidate))
      candidate)))

(defclass windows-sandbox-plan (sandbox-plan)
  ((profile :initarg :profile :reader windows-plan-profile)
   (rules :initarg :rules :reader windows-plan-rules))
  (:documentation "An AppContainer launch and the SID-specific ACL cleanup it owns."))

(defun windows--helper-command (helper arguments)
  "Run a trusted helper operation, requiring successful completion."
  (multiple-value-bind (output error-output status)
      (uiop:run-program (cons (uiop:native-namestring helper) arguments)
                        :input nil :output :string :error-output :string
                        :ignore-error-status t)
    (unless (zerop status)
      (error 'sandbox-execution-error
             :message (format nil "Windows sandbox helper failed (~D): ~A"
                              status error-output)
             :command (cons (uiop:native-namestring helper) arguments)))
    output))

(defun windows--new-profile (helper)
  "Ask the native helper for a cryptographically unique AppContainer name."
  (let ((name (string-trim '(#\Space #\Tab #\Return #\Newline)
                           (windows--helper-command helper '("--new-profile")))))
    (unless (and (<= 16 (length name) 100)
                 (uiop:string-prefix-p "cl-exec-sandbox." name)
                 (every (lambda (character)
                          (or (find character "abcdefghijklmnopqrstuvwxyz0123456789-.")
                              (find character "ABCDEF")))
                        name))
      (error 'sandbox-execution-error
             :message "The Windows helper returned an invalid AppContainer identity."
             :command (list (uiop:native-namestring helper) "--new-profile")))
    name))

(defmethod sandbox-plan-cleanup ((plan windows-sandbox-plan))
  "Remove only this invocation's package SID grants, including after cancellation."
  (windows--helper-command
   (sandbox-plan-program plan)
   (append (list "--cleanup" (windows-plan-profile plan))
           (windows-plan-rules plan)))
  nil)

(defun windows--unsupported (capability message)
  "Reject an AppContainer policy that this backend cannot enforce."
  (error 'sandbox-unavailable :capability capability :message message))

(defun windows--validate-policy (policy)
  "Validate the explicit-scope AppContainer policy before touching filesystem ACLs."
  (unless (eq (sandbox-policy-filesystem-kind policy) :restricted)
    (windows--unsupported :filesystem-read-only-host
                          "AppContainer requires explicit filesystem scopes, not a whole-host view."))
  (unless (eq (sandbox-policy-network policy) :isolated)
    (windows--unsupported :network-mode
                          "The AppContainer backend supports isolated networking only."))
  (when (or (sandbox-policy-mount-proc-p policy)
            (sandbox-policy-isolate-processes-p policy))
    (windows--unsupported :process-namespace
                          "AppContainer does not provide a proc mount or PID namespace."))
  (dolist (rule (sandbox-policy-filesystem-rules policy))
    (when (eq (filesystem-rule-kind rule) :glob)
      (windows--unsupported :filesystem-deny-globs
                            "AppContainer deny rules must name explicit existing paths."))
    (when (eq (filesystem-rule-kind rule) :special)
      (unless (eq (filesystem-rule-path rule) :workspace-roots)
        (windows--unsupported :filesystem-special-root
                              "AppContainer accepts workspace roots and explicit local paths only.")))))

(defun windows--validate-path (path)
  "Require a drive-qualified local path; native validation also checks filesystem aliases."
  (let ((native (uiop:native-namestring path)))
    (unless (and (> (length native) 3)
                 (alpha-char-p (char native 0))
                 (char= (char native 1) #\:)
                 (find (char native 2) '(#\/ #\\))
                 (not (find #\: native :start 2))
                 (notany (lambda (component) (member component '("." "..") :test #'string=))
                         (uiop:split-string native :separator '(#\/ #\\))))
      (windows--unsupported :filesystem-local-path
                            "AppContainer grants require local, non-root, drive-qualified paths without aliases."))
    native))

(defun windows--appcontainer-plan
    (program arguments policy cwd environment clear-environment-p)
  "Build a fail-closed AppContainer plan with invocation-scoped filesystem grants."
  (windows--validate-policy policy)
  (let ((helper (windows--find-helper))
        (created nil)
        (complete-p nil))
    (unless helper
      (windows--unsupported :platform-backend
                            "Build the Windows AppContainer helper or set CL_EXEC_SANDBOX_WINDOWS_HELPER."))
    (unwind-protect
         (let ((rules (rules--resolve-rules policy cwd))
               (native-rules nil))
           (dolist (rule rules)
             (let* ((path (resolved-filesystem-rule-path rule))
                    (native (windows--validate-path path)))
               (unless (probe-file path)
                 (unless (eq (resolved-filesystem-rule-origin rule) :protected-metadata)
                   (windows--unsupported :filesystem-existing-path
                                         "AppContainer grant roots must exist before launch."))
                 ;; Protect absent metadata names too, so the command cannot create
                 ;; a fresh unprotected .git under its writable workspace.
                 (ensure-directories-exist path)
                 (push path created))
               (setf native-rules
                     (append native-rules
                             (list (string-downcase
                                    (symbol-name (resolved-filesystem-rule-access rule)))
                                   native)))))
           (let* ((profile (windows--new-profile helper))
                  (plan
                    (make-instance 'windows-sandbox-plan
                     :program helper
                     :arguments (append (list "--run" profile "isolated"
                                              (uiop:native-namestring cwd))
                                        native-rules (list "--" (uiop:native-namestring program))
                                        arguments)
                     :environment environment
                     :environment-provided-p (or (not (null environment)) clear-environment-p)
                     :working-directory cwd
                     :cleanup-paths (reverse created)
                     :profile profile :rules native-rules)))
             (setf complete-p t)
             plan))
      (unless complete-p
        (dolist (path created)
          (ignore-errors (uiop:delete-empty-directory path)))))))

(defun appcontainer-sandbox-policy
    (&key workspace-roots read-roots
       (protected-metadata-names '(".git" ".agents" ".codex")))
  "Return an isolated-network policy with explicit writable workspaces and read scopes.

Windows supplies its AppContainer system read surface and private profile storage.
Whole-host read access and arbitrary network modes require a different backend."
  (unless workspace-roots
    (error 'sandbox-policy-error :message "An AppContainer policy needs a workspace root."))
  (make-sandbox-policy
   :workspace-roots workspace-roots
   :protected-metadata-names protected-metadata-names
   :network :isolated :mount-proc-p nil :isolate-processes-p nil
   :filesystem-rules
   (append (mapcar (lambda (path) (policy--path-rule path :read)) read-roots)
           (list (policy--special-rule :workspace-roots :write)))))
