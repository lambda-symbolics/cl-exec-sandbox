(in-package #:cl-exec-sandbox)

;;;; -- Platform Read Roots --

(defparameter +linux-platform-read-roots+
  '(#P"/bin/" #P"/sbin/" #P"/usr/" #P"/etc/" #P"/lib/" #P"/lib64/"
    #P"/nix/store/" #P"/run/current-system/sw/")
  "System roots exposed by the Linux backend for a :MINIMAL read rule.")

(defparameter +macos-platform-read-roots+
  '(#P"/bin/" #P"/sbin/" #P"/usr/" #P"/etc/" #P"/private/etc/"
    #P"/System/" #P"/Library/" #P"/opt/homebrew/" #P"/nix/store/")
  "System roots exposed by the macOS backend for a :MINIMAL read rule.")

(defun rules--platform-read-roots ()
  "Return the host's system read roots for a :MINIMAL filesystem rule.

An unrecognized operating system reuses the Linux roots, which name only
locations a POSIX host is likely to share."
  (if (member :darwin *features*)
      +macos-platform-read-roots+
      +linux-platform-read-roots+))


;;;; -- Resolved Rules --

(defstruct (resolved-filesystem-rule
            (:constructor rules--make-resolved-rule (path access origin)))
  "One absolute filesystem rule after special-path and glob expansion."
  (path #P"/" :type pathname)
  (access :read :type (member :read :write :deny))
  (origin :path :type keyword))

(defun rules--resolved-rule (path access origin)
  "Return a resolved rule for PATH with symbolic links resolved, so every
backend applies it where the host's file operations actually land."
  (rules--make-resolved-rule (path--canonical path) access origin))

(defun rules--special-paths (rule policy cwd)
  "Expand special RULE into absolute paths for POLICY and CWD."
  (case (filesystem-rule-path rule)
    (:root
     (list #P"/"))
    (:minimal
     (remove-if-not #'probe-file (rules--platform-read-roots)))
    (:workspace-roots
     (let ((subpath (and (filesystem-rule-subpath rule)
                         (path--safe-relative-subpath
                          (filesystem-rule-subpath rule)))))
       (mapcar (lambda (root)
                 (if subpath
                     (merge-pathnames subpath root)
                     root))
               (sandbox-policy-workspace-roots policy))))
    (:tmpdir
     (list (uiop:ensure-directory-pathname
            (path--absolute
             (or (uiop:getenv "TMPDIR") (uiop:temporary-directory)) cwd))))
    (:slash-tmp
     (list #P"/tmp/"))))


;;;; -- Deny Glob Expansion --

(defun rules--find-rg ()
  "Return the configured or PATH-resolved ripgrep pathname, excluding CWD."
  (let ((override (uiop:getenv "CL_EXEC_SANDBOX_RG"))
        (cwd (uiop:getcwd)))
    (or (when (and override (path--executable-file-p (pathname override)))
          (truename override))
        (loop for candidate in '(#P"/usr/bin/rg" #P"/bin/rg")
              when (path--executable-file-p candidate)
                return (truename candidate))
        (loop for directory in (path--directories)
              for candidate = (merge-pathnames "rg" directory)
              when (and (not (path--under-p candidate cwd))
                        (path--executable-file-p candidate))
                return (truename candidate)))))

(defun rules--run-rg-glob (pattern root maximum-depth)
  "Return existing paths below ROOT matching git-style PATTERN through ripgrep."
  (let ((rg (rules--find-rg)))
    (unless rg
      (error 'sandbox-unavailable
             :message "Deny-glob expansion requires ripgrep."
             :capability :filesystem-deny-globs))
    (let ((arguments (list (uiop:native-namestring rg)
                           "--files" "--hidden" "--no-ignore" "--null"
                           "--glob" pattern)))
      (when maximum-depth
        (setf arguments
              (append arguments
                      (list "--max-depth" (write-to-string maximum-depth)))))
      (setf arguments
            (append arguments (list "--" (uiop:native-namestring root))))
      (multiple-value-bind (output error-output status)
          (uiop:run-program arguments
                            :output :string
                            :error-output :string
                            :ignore-error-status t)
        (declare (ignore error-output))
        (unless (member status '(0 1))
          (error 'sandbox-policy-error
                 :message (format nil "Could not expand deny glob ~S below ~A."
                                  pattern root)))
        (if (zerop (length output))
            nil
            (loop for path in (uiop:split-string output :separator (list #\Null))
                  when (plusp (length path))
                    collect (path--absolute path root)))))))

(defun rules--expand-glob-rule (rule policy cwd)
  "Expand one deny-glob RULE below POLICY's project roots or CWD."
  (let ((roots (or (sandbox-policy-workspace-roots policy) (list cwd))))
    (loop for root in roots
          append (rules--run-rg-glob
                  (filesystem-rule-path rule)
                  root
                  (sandbox-policy-glob-scan-maximum-depth policy)))))


;;;; -- Resolution --

(defun rules--metadata-rules (policy)
  "Return read-only metadata rules nested below writable project roots."
  (loop for root in (sandbox-policy-workspace-roots policy)
        append
        (loop for name in (sandbox-policy-protected-metadata-names policy)
              collect (rules--resolved-rule
                       (merge-pathnames
                        (uiop:ensure-directory-pathname name)
                        root)
                       :read
                       :protected-metadata))))

(defun rules--resolve-rules (policy cwd)
  "Return POLICY's absolute rules sorted from broadest to most specific.

Backends that resolve overlapping rules by last match apply the result in
order. Backends that mount each rule separately apply the same order so that
a nested rule is established after the rule it narrows."
  (let ((rules nil))
    (when (eq (sandbox-policy-filesystem-kind policy) :unrestricted)
      (push (rules--resolved-rule #P"/" :write :unrestricted) rules))
    (dolist (rule (sandbox-policy-filesystem-rules policy))
      (ecase (filesystem-rule-kind rule)
        (:path
         (push (rules--resolved-rule
                (path--absolute (filesystem-rule-path rule) cwd)
                (filesystem-rule-access rule)
                :path)
               rules))
        (:special
         (dolist (path (rules--special-paths rule policy cwd))
           (push (rules--resolved-rule path
                                       (filesystem-rule-access rule)
                                       :special)
                 rules)))
        (:glob
         (dolist (path (rules--expand-glob-rule rule policy cwd))
           (push (rules--resolved-rule path :deny :glob) rules)))))
    (setf rules (append rules (rules--metadata-rules policy)))
    (stable-sort
     rules
     (lambda (left right)
       (let ((left-depth (length (path--components
                                  (resolved-filesystem-rule-path left))))
             (right-depth (length (path--components
                                   (resolved-filesystem-rule-path right)))))
         (if (= left-depth right-depth)
             (< (position (resolved-filesystem-rule-access left)
                          '(:read :write :deny))
                (position (resolved-filesystem-rule-access right)
                          '(:read :write :deny)))
             (< left-depth right-depth)))))))
