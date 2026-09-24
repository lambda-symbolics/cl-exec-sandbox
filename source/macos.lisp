(in-package #:cl-exec-sandbox)

;;;; -- Seatbelt Discovery --

(defun macos--find-sandbox-exec ()
  "Return the configured or trusted system Seatbelt launcher pathname."
  (let ((override (uiop:getenv "CL_EXEC_SANDBOX_SEATBELT"))
        (system   #P"/usr/bin/sandbox-exec"))
    (or (when (and override
                   (uiop:absolute-pathname-p (pathname override))
                   (path--executable-file-p (pathname override)))
          (truename override))
        (when (path--executable-file-p system)
          (truename system)))))


;;;; -- Profile Filters --

(defparameter +macos-baseline-operations+
  '("(allow process*)"
    "(allow signal (target same-sandbox))"
    "(allow sysctl-read)"
    "(allow mach-lookup)")
  "Non-filesystem operations every profile grants so a command can start.

Denying a process launch, a signal, a sysctl read, or a Mach lookup stops even
a trivial command from running on macOS. Signals reach only processes in the
same sandbox, so a command can manage its own descendants but never signal
the user's other processes.")

(defparameter +macos-device-operation+
  "(allow file-read* file-write* (subpath \"/dev\"))"
  "Device access granted after whole-root rules and before narrower rules.

This mirrors where the Linux backend mounts /dev: after the root bind, so a
read-only root cannot revoke it, and before deeper rules, so a policy that
names a device path explicitly still wins.")

(defun macos--quoted-string (text)
  "Return TEXT quoted and escaped for a Seatbelt profile string literal."
  (with-output-to-string (stream)
    (write-char #\" stream)
    (loop for character across text
          do (when (or (char= character #\\)
                       (char= character #\"))
               (write-char #\\ stream))
             (write-char character stream))
    (write-char #\" stream)))

(defun macos--path-string (path)
  "Return PATH as a Seatbelt path string without a trailing slash."
  (let ((namestring (uiop:native-namestring path)))
    (if (string= namestring "/")
        namestring
        (string-right-trim '(#\/) namestring))))

(defun macos--directory-path-p (path)
  "Return true when PATH names a directory subtree rather than a single file."
  (let ((probed (probe-file path)))
    (not (null (or (uiop:directory-pathname-p path)
                   (and probed (uiop:directory-pathname-p probed)))))))

(defun macos--path-filter (path &optional literal-p)
  "Return the Seatbelt filter selecting PATH.

A directory becomes a subpath filter covering its whole subtree. Any other path,
or any path when LITERAL-P is true, becomes a literal filter naming exactly one
file, so a rule on a file or a symbolic link cannot silently widen."
  (format nil "(~A ~A)"
          (if (and (not literal-p) (macos--directory-path-p path))
              "subpath"
              "literal")
          (macos--quoted-string (macos--path-string path))))

(defun macos--root-rule-p (rule)
  "Return true when RULE applies to the whole filesystem root."
  (string= (macos--path-string (resolved-filesystem-rule-path rule)) "/"))

(defun macos--rule-operations (rule)
  "Return the Seatbelt operations enforcing one resolved RULE.

Seatbelt resolves overlapping rules by last match, and resolved rules arrive
broadest first, so a narrower rule must restate every operation it changes. A
read rule therefore denies writes explicitly: without that it would inherit the
write allowance of the writable root it is nested inside, which is exactly the
case for protected metadata directories."
  (let ((filter (macos--path-filter
                 (resolved-filesystem-rule-path rule)
                 (eq (resolved-filesystem-rule-origin rule) :link))))
    (ecase (resolved-filesystem-rule-access rule)
      (:read
       (list (format nil "(allow file-read* ~A)" filter)
             (format nil "(deny file-write* ~A)" filter)))
      (:write
       (list (format nil "(allow file-read* file-write* ~A)" filter)))
      (:deny
       (list (format nil "(deny file-read* file-write* ~A)" filter))))))

(defun macos--hidden-ancestors (rules)
  "Return the directories inside denied RULES that lead to a granted rule.

A lookup below a denied directory succeeds without reading its ancestors, but
getcwd, realpath, and shells inspect each ancestor's metadata, so those
ancestors must answer metadata queries while their contents stay hidden."
  (let ((denied (remove-if-not (lambda (rule)
                                 (eq (resolved-filesystem-rule-access rule) :deny))
                               rules))
        (ancestors nil))
    (dolist (rule rules)
      (unless (eq (resolved-filesystem-rule-access rule) :deny)
        (let ((components (path--components (resolved-filesystem-rule-path rule))))
          (loop for count from 1 below (length components)
                for ancestor = (uiop:parse-native-namestring
                                (format nil "/~{~A~^/~}/" (subseq components 0 count)))
                when (some (lambda (deny)
                             (path--under-p ancestor (resolved-filesystem-rule-path deny)))
                           denied)
                  do (pushnew (macos--path-string ancestor) ancestors :test #'string=)))))
    (sort ancestors #'string<)))


;;;; -- Seatbelt Profile --

(defun macos--seatbelt-profile (policy cwd)
  "Translate POLICY into a macOS Seatbelt profile for a command run in CWD.

The profile denies every operation by default, grants the operations a command
needs to start, then applies POLICY's resolved filesystem rules from the
broadest to the most specific so that Seatbelt's last-match-wins resolution
reproduces the policy. Whole-root rules are emitted before device access so a
read-only root cannot revoke it.

Seatbelt provides no user, process, IPC, UTS, or PID namespace, so
SANDBOX-POLICY-ISOLATE-PROCESSES-P and SANDBOX-POLICY-MOUNT-PROC-P are not
enforced by this backend. SANDBOX-CAPABILITIES reports that absence, and a
policy requesting them is translated without them rather than rejected."
  (when (eq (sandbox-policy-network policy) :proxy-only)
    (error 'sandbox-unavailable
           :message "Seatbelt cannot enforce a proxy-only network policy."
           :capability :network-proxy-only))
  (let ((rules (rules--resolve-rules policy cwd)))
    (with-output-to-string (stream)
      (format stream "(version 1)~%(deny default)~%")
      (dolist (operation +macos-baseline-operations+)
        (format stream "~A~%" operation))
      (dolist (rule (remove-if-not #'macos--root-rule-p rules))
        (dolist (operation (macos--rule-operations rule))
          (format stream "~A~%" operation)))
      (format stream "~A~%" +macos-device-operation+)
      (dolist (rule (remove-if #'macos--root-rule-p rules))
        (dolist (operation (macos--rule-operations rule))
          (format stream "~A~%" operation)))
      (dolist (ancestor (macos--hidden-ancestors rules))
        (format stream "(allow file-read-metadata (literal ~A))~%"
                (macos--quoted-string ancestor)))
      (format stream "(~A network*)~%"
              (ecase (sandbox-policy-network policy)
                (:enabled "allow")
                (:isolated "deny"))))))


;;;; -- Seatbelt Plan --

(defun macos--seatbelt-plan
    (program arguments policy cwd environment clear-environment-p)
  "Return a Seatbelt launch plan for PROGRAM and ARGUMENTS under POLICY.

The profile is passed on the command line, so no temporary profile file is
created and the plan carries no cleanup obligations."
  (let ((sandbox-exec (macos--find-sandbox-exec)))
    (unless sandbox-exec
      (error 'sandbox-unavailable
             :message "A restricted macOS sandbox requires the Seatbelt launcher."
             :capability :seatbelt))
    (make-instance 'sandbox-plan
                   :program sandbox-exec
                   :arguments (append (list "-p"
                                            (macos--seatbelt-profile policy cwd)
                                            (uiop:native-namestring program))
                                      arguments)
                   :environment environment
                   :environment-provided-p
                   (not (null (or environment clear-environment-p)))
                   :working-directory cwd
                   :cleanup-paths nil)))
