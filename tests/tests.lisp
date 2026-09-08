(in-package #:cl-exec-sandbox/tests)

(defvar *test-count* 0
  "The number of assertions completed by the current test run.")

(defun test-assert (condition description)
  "Require CONDITION and count it as DESCRIPTION."
  (unless condition
    (error "Test failed: ~A" description))
  (incf *test-count*)
  t)

(defun tests--temporary-root ()
  "Create and return a fresh temporary test directory."
  (let ((root
          (merge-pathnames
           (format nil "cl-exec-sandbox-test-~36R-~36R/"
                   (get-universal-time) (random most-positive-fixnum))
           (uiop:temporary-directory))))
    (ensure-directories-exist root)
    root))

(defun tests--write (path text)
  "Write TEXT to PATH and return PATH."
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-does-not-exist :create
                          :if-exists :supersede)
    (write-string text stream))
  path)

(defun test-executable-file-detection ()
  "Test executable regular files, symlinks and rejected filesystem objects."
  (let* ((root (tests--temporary-root))
         (executable (merge-pathnames "executable" root))
         (plain (merge-pathnames "plain" root))
         (link (merge-pathnames "executable-link" root))
         (dangling (merge-pathnames "dangling-link" root))
         (missing (merge-pathnames "missing" root))
         (fifo (merge-pathnames "fifo" root)))
    (unwind-protect
         (progn
           (tests--write executable "fixture")
           (tests--write plain "fixture")
           (sb-posix:chmod (uiop:native-namestring executable) #o700)
           (sb-posix:chmod (uiop:native-namestring plain) #o600)
           (sb-posix:symlink (uiop:native-namestring executable)
                             (uiop:native-namestring link))
           (sb-posix:symlink (uiop:native-namestring missing)
                             (uiop:native-namestring dangling))
           (sb-posix:mkfifo (uiop:native-namestring fifo) #o700)
           (dolist (case (list (cons executable t)
                              (cons link t)
                              (cons plain nil)
                              (cons root nil)
                              (cons fifo nil)
                              (cons missing nil)
                              (cons dangling nil)))
             (test-assert
              (eq (cl-exec-sandbox::path--executable-file-p (first case))
                  (rest case))
              (format nil "executable file detection for ~A" (first case)))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-policy-validation ()
  "Test policy presets, malformed rules, and capability discovery."
  (let ((policy
          (workspace-write-sandbox-policy
           :workspace-roots (list (uiop:getcwd)))))
    (test-assert (eq (sandbox-policy-network policy) :isolated)
                 "workspace-write defaults to isolated networking")
    (test-assert (= (length (sandbox-policy-filesystem-rules policy)) 4)
                 "workspace-write grants root read, project write, and temp writes")
    (test-assert
     (handler-case
         (progn
           (make-filesystem-rule :kind :glob :path "*.key" :access :read)
           nil)
       (sandbox-policy-error ()
         t))
     "glob rules reject positive access")
    (test-assert (getf (sandbox-capabilities) :filesystem-read-write-deny)
                 "Linux capability discovery finds bubblewrap"))
  nil)

(defun test-bwrap-override ()
  "Test an explicit absolute Bubblewrap path supports packaged installations."
  (let* ((expected (or (probe-file #P"/usr/bin/bwrap")
                       (probe-file #P"/bin/bwrap")))
         (previous (uiop:getenv "CL_EXEC_SANDBOX_BWRAP")))
    (when expected
      (unwind-protect
           (progn
             (sb-posix:setenv "CL_EXEC_SANDBOX_BWRAP"
                              (uiop:native-namestring expected)
                              1)
             (test-assert
              (equal (truename expected)
                     (cl-exec-sandbox::linux--find-bwrap))
              "an explicit absolute Bubblewrap path is honored"))
        (if previous
            (sb-posix:setenv "CL_EXEC_SANDBOX_BWRAP" previous 1)
            (sb-posix:unsetenv "CL_EXEC_SANDBOX_BWRAP")))))
  nil)

(defun test-seatbelt-override ()
  "Test an explicit absolute Seatbelt path supports packaged installations."
  (let* ((expected (or (probe-file #P"/usr/bin/sandbox-exec")
                       (probe-file #P"/bin/sh")))
         (previous (uiop:getenv "CL_EXEC_SANDBOX_SEATBELT")))
    (when expected
      (unwind-protect
           (progn
             (sb-posix:setenv "CL_EXEC_SANDBOX_SEATBELT"
                              (uiop:native-namestring expected)
                              1)
             (test-assert
              (equal (truename expected)
                     (cl-exec-sandbox::macos--find-sandbox-exec))
              "an explicit absolute Seatbelt path is honored"))
        (if previous
            (sb-posix:setenv "CL_EXEC_SANDBOX_SEATBELT" previous 1)
            (sb-posix:unsetenv "CL_EXEC_SANDBOX_SEATBELT")))))
  nil)

(defun tests--seatbelt-profile (policy)
  "Return POLICY translated into a Seatbelt profile for the current directory."
  (cl-exec-sandbox::macos--seatbelt-profile policy (uiop:getcwd)))

(defun tests--before-p (profile earlier later)
  "Return true when EARLIER appears in PROFILE strictly before LATER."
  (let ((earlier-position (search earlier profile))
        (later-position (search later profile)))
    (and earlier-position
         later-position
         (< earlier-position later-position))))

(defun test-seatbelt-profile-translation ()
  "Test Seatbelt profile translation, rule ordering, and unsupported policies.

Profile text is a pure function of a policy, so these assertions run on any
host. They do not verify that macOS enforces the profile."
  (let ((profile (tests--seatbelt-profile (read-only-sandbox-policy))))
    (test-assert (tests--before-p profile "(version 1)" "(deny default)")
                 "a profile opens by denying every operation")
    (test-assert (search "(allow process*)" profile)
                 "a profile grants the operations a command needs to start")
    (test-assert (search "(allow file-read* (subpath \"/\"))" profile)
                 "a read-only root policy allows reads everywhere")
    (test-assert (search "(deny file-write* (subpath \"/\"))" profile)
                 "a read-only root policy denies writes everywhere")
    (test-assert (tests--before-p profile
                                 "(deny file-write* (subpath \"/\"))"
                                 "(allow file-read* file-write* (subpath \"/dev\"))")
                 "device access survives a read-only root")
    (test-assert (search "(deny network*)" profile)
                 "an isolated policy denies networking"))
  (test-assert (search "(allow network*)"
                       (tests--seatbelt-profile
                        (read-only-sandbox-policy :network :enabled)))
               "an enabled policy allows networking")
  (test-assert
   (handler-case
       (progn (tests--seatbelt-profile
               (read-only-sandbox-policy :network :proxy-only))
              nil)
     (sandbox-unavailable (condition)
       (eq (sandbox-unavailable-capability condition) :network-proxy-only)))
   "Seatbelt reports that it cannot enforce a proxy-only network")
  (test-assert (search "(allow file-read* file-write* (subpath \"/\"))"
                       (tests--seatbelt-profile
                        (unrestricted-sandbox-policy :network :isolated)))
               "an unrestricted policy allows writes everywhere")
  (let* ((root (tests--temporary-root))
         (metadata (string-right-trim
                    "/"
                    (uiop:native-namestring (merge-pathnames ".git/" root)))))
    (unwind-protect
         (let ((profile
                 (tests--seatbelt-profile
                  (workspace-write-sandbox-policy
                   :workspace-roots (list root)
                   :protected-metadata-names '(".git")))))
           (test-assert
            (search (format nil "(allow file-read* file-write* (subpath ~S))"
                            (string-right-trim "/" (uiop:native-namestring root)))
                    profile)
            "a workspace root becomes writable")
           (test-assert (search (format nil "(deny file-write* (subpath ~S))"
                                        metadata)
                                profile)
                        "protected metadata denies writes")
           (test-assert
            (tests--before-p
             profile
             (format nil "(allow file-read* file-write* (subpath ~S))"
                     (string-right-trim "/" (uiop:native-namestring root)))
             (format nil "(deny file-write* (subpath ~S))" metadata))
            "protected metadata is denied after its writable root")
           (test-assert (search "(allow file-read* file-write* (subpath \"/tmp\"))"
                                profile)
                        "a workspace-write policy keeps /tmp writable"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  (let* ((root (tests--temporary-root))
         (file (tests--write (merge-pathnames "token.key" root) "secret")))
    (unwind-protect
         (let ((profile
                 (tests--seatbelt-profile
                  (make-sandbox-policy
                   :workspace-roots (list root)
                   :filesystem-rules
                   (list (make-filesystem-rule :kind :special
                                               :path :root
                                               :access :read)
                         (make-filesystem-rule :kind :path
                                               :path file
                                               :access :deny))))))
           (test-assert
            (search (format nil "(deny file-read* file-write* (literal ~S))"
                            (uiop:native-namestring file))
                    profile)
            "a rule naming one file uses a literal filter")
           (test-assert
            (not (search (format nil "(subpath ~S)"
                                 (uiop:native-namestring file))
                         profile))
            "a rule naming one file does not widen to a subpath"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  (test-assert (string= (cl-exec-sandbox::macos--quoted-string "a\"b\\c")
                        "\"a\\\"b\\\\c\"")
               "profile strings escape quotes and backslashes")
  nil)

(defun test-read-only-enforcement ()
  "Test a read-only policy permits reads and rejects host writes."
  (let* ((root (tests--temporary-root))
         (file (tests--write (merge-pathnames "value.txt" root) "before"))
         (policy (read-only-sandbox-policy)))
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/sh"
                  (list "-c"
                        (format nil "cat ~A; printf after > ~A"
                                (uiop:escape-shell-token
                                 (uiop:native-namestring file))
                                (uiop:escape-shell-token
                                 (uiop:native-namestring file))))
                  :policy policy
                  :working-directory root)))
           (test-assert (not (zerop (sandbox-result-exit-code result)))
                        "read-only execution rejects a write")
           (test-assert (search "before" (sandbox-result-output result))
                        "read-only execution still permits a read")
           (test-assert (string= (uiop:read-file-string file) "before")
                        "the rejected write leaves the host file unchanged"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-workspace-write-enforcement ()
  "Test workspace writes, outside rejection, and protected metadata carve-outs."
  (let* ((root (tests--temporary-root))
         (outside (tests--temporary-root))
         (git-directory (merge-pathnames ".git/" root))
         (git-file (tests--write (merge-pathnames "config" git-directory) "safe"))
         (workspace-file (merge-pathnames "created.txt" root))
         (outside-file (merge-pathnames "blocked.txt" outside))
         (policy
           (workspace-write-sandbox-policy :workspace-roots (list root)
                                           :write-tmpdir-p nil
                                           :write-slash-tmp-p nil)))
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/sh"
                  (list
                   "-c"
                   (format nil
                           "printf yes > ~A; printf no > ~A; printf bad > ~A"
                           (uiop:escape-shell-token
                            (uiop:native-namestring workspace-file))
                           (uiop:escape-shell-token
                            (uiop:native-namestring outside-file))
                           (uiop:escape-shell-token
                            (uiop:native-namestring git-file))))
                  :policy policy
                  :working-directory root)))
           (test-assert (probe-file workspace-file)
                        "workspace-write publishes a file below the project root")
           (test-assert (not (probe-file outside-file))
                        "workspace-write rejects a file outside the project root")
           (test-assert (string= (uiop:read-file-string git-file) "safe")
                        "protected metadata remains read-only")
           (test-assert (not (zerop (sandbox-result-exit-code result)))
                        "a rejected write is visible in the command status"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)
      (uiop:delete-directory-tree outside :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-missing-protected-metadata ()
  "Test a missing protected metadata path cannot be created or left behind."
  (let* ((root (tests--temporary-root))
         (metadata (merge-pathnames ".agents/" root))
         (policy
           (workspace-write-sandbox-policy :workspace-roots (list root)
                                           :write-tmpdir-p nil
                                           :write-slash-tmp-p nil)))
    (unwind-protect
         (let ((result
                 (run-sandboxed "/bin/sh" '("-c" "mkdir .agents")
                                :policy policy
                                :working-directory root)))
           (test-assert (not (zerop (sandbox-result-exit-code result)))
                        "missing protected metadata rejects creation")
           (test-assert (not (probe-file metadata))
                        "synthetic metadata target is removed after execution"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-deny-and-nested-override ()
  "Test deny masks and a more-specific writable child below a denied parent."
  (let* ((root (tests--temporary-root))
         (blocked (merge-pathnames "blocked/" root))
         (allowed (merge-pathnames "allowed/" blocked))
         (secret (tests--write (merge-pathnames "secret.txt" blocked) "secret"))
         (output (merge-pathnames "new.txt" allowed)))
    (ensure-directories-exist output)
    (let ((policy
            (make-sandbox-policy
             :workspace-roots (list root)
             :filesystem-rules
             (list
              (make-filesystem-rule :kind :special :path :root :access :read)
              (make-filesystem-rule :kind :path :path root :access :write)
              (make-filesystem-rule :kind :path :path blocked :access :deny)
              (make-filesystem-rule :kind :path :path allowed :access :write)))))
      (unwind-protect
           (let ((result
                   (run-sandboxed
                    "/bin/sh"
                    (list "-c"
                          (format nil "cat ~A 2>/dev/null || true; printf ok > ~A"
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring secret))
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring output))))
                    :policy policy
                    :working-directory root)))
             (test-assert (not (search "secret" (sandbox-result-output result)))
                          "an exact deny masks readable content")
             (test-assert (string= (uiop:read-file-string output) "ok")
                          "a narrower write rule reopens a denied parent"))
        (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))
  nil)

(defun test-deny-glob ()
  "Test a deny glob masks matching files without masking other project files."
  (let* ((root (tests--temporary-root))
         (secret (tests--write (merge-pathnames "private.key" root) "secret"))
         (public (tests--write (merge-pathnames "public.txt" root) "public"))
         (policy
           (make-sandbox-policy
            :workspace-roots (list root)
            :filesystem-rules
            (list
             (make-filesystem-rule :kind :special :path :root :access :read)
             (make-filesystem-rule :kind :path :path root :access :write)
             (make-filesystem-rule :kind :glob :path "*.key" :access :deny)))))
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/sh"
                  (list "-c"
                        (format nil "cat ~A 2>/dev/null || true; cat ~A"
                                (uiop:escape-shell-token
                                 (uiop:native-namestring secret))
                                (uiop:escape-shell-token
                                 (uiop:native-namestring public))))
                  :policy policy
                  :working-directory root)))
           (test-assert (string= (sandbox-result-output result) "public")
                        "deny glob hides only matching content"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-unrestricted-filesystem-with-isolated-network ()
  "Test network isolation does not accidentally narrow an unrestricted filesystem."
  (let* ((root (tests--temporary-root))
         (output (merge-pathnames "created.txt" root))
         (result
           (run-sandboxed
            "/bin/sh"
            (list "-c"
                  (format nil "printf ok > ~A"
                          (uiop:escape-shell-token
                           (uiop:native-namestring output))))
            :policy (unrestricted-sandbox-policy :network :isolated))))
    (unwind-protect
         (progn
           (test-assert (zerop (sandbox-result-exit-code result))
                        "unrestricted filesystem command succeeds")
           (test-assert (string= (uiop:read-file-string output) "ok")
                        "unrestricted filesystem stays writable"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-external-execution-context ()
  "Test direct execution honors its working directory and explicit environment."
  (let* ((root (tests--temporary-root))
         (result
           (run-sandboxed
            "/bin/sh" '("-c" "printf '%s|%s' \"$PWD\" \"$VALUE\"")
            :policy (external-sandbox-policy)
            :working-directory root
            :environment '("VALUE=present"))))
    (unwind-protect
         (test-assert
          (string= (sandbox-result-output result)
                   (format nil "~A|present"
                           (string-right-trim
                            "/"
                            (uiop:native-namestring root))))
          "direct execution applies working directory and environment")
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-process-group-platform-support ()
  "Test direct supervision covers every supported POSIX release target."
  (dolist (feature '(:linux :darwin :freebsd :netbsd :openbsd))
    (let ((*features* (list feature)))
      (test-assert
       (cl-exec-sandbox::posix--process-group-supported-p)
       (format nil "~A enables process-group supervision" feature))))
  (let ((*features* '(:windows)))
    (test-assert
     (not (cl-exec-sandbox::posix--process-group-supported-p))
     "Windows does not claim POSIX process-group supervision"))
  nil)

(defun test-timeout ()
  "Test deadline supervision terminates a sandbox process."
  (let ((result
          (run-sandboxed "/bin/sh" '("-c" "sleep 5")
                         :policy (read-only-sandbox-policy)
                         :timeout 0.05)))
    (test-assert (sandbox-result-timed-out-p result)
                 "a command exceeding its deadline is marked timed out")
    (test-assert (< (sandbox-result-real-seconds result) 2)
                 "deadline supervision returns promptly"))
  nil)

(defun test-direct-timeout-descendant-cleanup ()
  "Test direct timeout kills a background descendant process."
  (let* ((root (tests--temporary-root))
         (finished (merge-pathnames "finished" root))
         (result
           (run-sandboxed
            "/bin/sh"
            (list
             "-c"
             (format nil
                     "(sleep 0.3; printf finished > ~A) & wait"
                     (uiop:escape-shell-token
                      (uiop:native-namestring finished))))
            :policy (unrestricted-sandbox-policy)
            :timeout 0.05)))
    (unwind-protect
         (progn
           (sleep 0.5)
           (test-assert (sandbox-result-timed-out-p result)
                        "a direct command exceeding its deadline is marked timed out")
           (test-assert (not (probe-file finished))
                        "a background descendant cannot survive direct timeout"))
      (uiop:delete-directory-tree root :validate t
                                       :if-does-not-exist :ignore)))
  nil)

(defun test-interrupted-execution-cleanup ()
  "Test a nonlocal exit terminates and reaps the launched process."
  (let* ((root (tests--temporary-root))
         (started (merge-pathnames "started" root))
         (finished (merge-pathnames "finished" root))
         (thread nil)
         (interrupted-p nil))
    (unwind-protect
         (progn
           (setf thread
                 (sb-thread:make-thread
                  (lambda ()
                    (handler-case
                        (run-sandboxed
                         "/bin/sh"
                         (list
                          "-c"
                          (format nil
                                  "printf started > ~A; (sleep 1; printf finished > ~A) & wait"
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring started))
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring finished))))
                         :policy (unrestricted-sandbox-policy))
                      (serious-condition ()
                        (setf interrupted-p t))))
                  :name "cl-exec-sandbox interruption test"))
           (test-assert
            (loop repeat 200
                  when (probe-file started)
                    return t
                  do (sleep 0.01)
                  finally (return nil))
            "the interrupted command starts before cancellation")
           (sb-thread:interrupt-thread
            thread
            (lambda ()
              (error "Interrupt sandbox execution for cleanup testing.")))
           (sb-thread:join-thread thread)
           (setf thread nil)
           (test-assert interrupted-p
                        "the caller observes its nonlocal execution exit")
           (sleep 1.2)
           (test-assert (not (probe-file finished))
                        "the interrupted command cannot continue after cleanup"))
      (when (and thread (sb-thread:thread-alive-p thread))
        (ignore-errors
          (sb-thread:interrupt-thread
           thread
           (lambda ()
             (error "Stop interrupted execution test cleanup."))))
        (ignore-errors (sb-thread:join-thread thread :default nil)))
      (uiop:delete-directory-tree root :validate t
                                       :if-does-not-exist :ignore)))
  nil)

(defun test-interrupted-launch-ownership ()
  "Test cancellation cannot outrun ownership of a newly launched process."
  (let* ((root (tests--temporary-root))
         (finished (merge-pathnames "finished" root))
         (launch-entered (sb-thread:make-semaphore))
         (launch-release (sb-thread:make-semaphore))
         (launch-function
           (symbol-function 'cl-exec-sandbox::execute--launch-plan))
         (thread nil)
         (interrupted-p nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'cl-exec-sandbox::execute--launch-plan)
                 (lambda (&rest arguments)
                   (let ((process (apply launch-function arguments)))
                     (sb-thread:signal-semaphore launch-entered)
                     (sb-thread:wait-on-semaphore launch-release)
                     process)))
           (setf thread
                 (sb-thread:make-thread
                  (lambda ()
                    (handler-case
                        (run-sandboxed
                         "/bin/sh"
                         (list
                          "-c"
                          (format nil
                                  "sleep 0.2; printf finished > ~A"
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring finished))))
                         :policy (external-sandbox-policy))
                      (serious-condition ()
                        (setf interrupted-p t))))
                  :name "cl-exec-sandbox launch ownership test"))
           (test-assert
            (sb-thread:wait-on-semaphore launch-entered :timeout 2)
            "the ownership test pauses after the process launch")
           (sb-thread:interrupt-thread
            thread
            (lambda ()
              (error "Interrupt the process ownership handoff.")))
           (sb-thread:signal-semaphore launch-release)
           (sb-thread:join-thread thread)
           (setf thread nil)
           (test-assert interrupted-p
                        "the launch ownership interruption reaches its caller")
           (sleep 0.4)
           (test-assert
            (not (probe-file finished))
            "an interrupted ownership handoff still terminates the process"))
      (setf (symbol-function 'cl-exec-sandbox::execute--launch-plan)
            launch-function)
      (sb-thread:signal-semaphore launch-release)
      (when (and thread (sb-thread:thread-alive-p thread))
        (ignore-errors
          (sb-thread:interrupt-thread
           thread
           (lambda ()
             (error "Stop launch ownership test cleanup."))))
        (ignore-errors (sb-thread:join-thread thread :default nil)))
      (uiop:delete-directory-tree root :validate t
                                       :if-does-not-exist :ignore)))
  nil)

(defun test-merged-output ()
  "Test callers can retain the original ordering of standard output and error."
  (let ((result
          (run-sandboxed
           "/bin/sh"
           '("-c" "printf one; printf two >&2; printf three")
           :policy (read-only-sandbox-policy)
           :merge-output-p t)))
    (test-assert (string= (sandbox-result-output result) "onetwothree")
                 "merged command output preserves stream write order")
    (test-assert (string= (sandbox-result-error-output result) "")
                 "merged command output leaves no duplicate error stream"))
  nil)

(defun test-output-capture-limits ()
  "Test bounded output capture and explicit truncation metadata."
  (let ((exact
          (run-sandboxed "/bin/sh" '("-c" "printf 12345; printf abc >&2")
                         :policy (read-only-sandbox-policy)
                         :output-limit 5
                         :error-output-limit 3))
        (truncated
          (run-sandboxed "/bin/sh" '("-c" "printf 123456; printf abcd >&2")
                         :policy (read-only-sandbox-policy)
                         :output-limit 5
                         :error-output-limit 3))
        (merged
          (run-sandboxed "/bin/sh" '("-c" "printf one; printf two >&2")
                         :policy (read-only-sandbox-policy)
                         :merge-output-p t
                         :output-limit 4
                         :error-output-limit 4))
        (zero
          (run-sandboxed "/bin/sh" '("-c" "printf x")
                         :policy (read-only-sandbox-policy)
                         :output-limit 0))
        (large
          (run-sandboxed
           "/bin/sh"
           '("-c" "head -c 16777216 /dev/zero | tr '\\000' x")
           :policy (read-only-sandbox-policy)
           :output-limit 1024)))
    (test-assert (string= (sandbox-result-output exact) "12345")
                 "an exactly full standard output is retained")
    (test-assert (not (sandbox-result-output-truncated-p exact))
                 "an exactly full standard output is not marked truncated")
    (test-assert (string= (sandbox-result-error-output exact) "abc")
                 "an exactly full standard error is retained")
    (test-assert (not (sandbox-result-error-output-truncated-p exact))
                 "an exactly full standard error is not marked truncated")
    (test-assert (string= (sandbox-result-output truncated) "12345")
                 "standard output is capped at its configured limit")
    (test-assert (sandbox-result-output-truncated-p truncated)
                 "capped standard output is marked truncated")
    (test-assert (string= (sandbox-result-error-output truncated) "abc")
                 "standard error is capped independently")
    (test-assert (sandbox-result-error-output-truncated-p truncated)
                 "capped standard error is marked truncated")
    (test-assert (string= (sandbox-result-output merged) "onet")
                 "merged output uses the standard output limit")
    (test-assert (sandbox-result-output-truncated-p merged)
                 "capped merged output is marked truncated")
    (test-assert (string= (sandbox-result-error-output merged) "")
                 "merged output leaves standard error empty")
    (test-assert (not (sandbox-result-error-output-truncated-p merged))
                 "empty merged standard error is not marked truncated")
    (test-assert (string= (sandbox-result-output zero) "")
                 "a zero output limit captures no characters")
    (test-assert (sandbox-result-output-truncated-p zero)
                 "a zero output limit detects available output")
    (test-assert (= (length (sandbox-result-output large)) 1024)
                 "large command output remains bounded")
    (test-assert (sandbox-result-output-truncated-p large)
                 "large command output reports truncation")
    (test-assert
     (handler-case
         (progn
           (run-sandboxed "/bin/true" nil
                          :policy (read-only-sandbox-policy)
                          :output-limit -1)
           nil)
       (sandbox-policy-error ()
         t))
     "negative output limits are rejected"))
  nil)

(defun test-isolated-network-seccomp ()
  "Test restricted networking denies Internet socket creation with seccomp."
  (let ((result
          (run-sandboxed
           "/bin/bash"
           '("-c" "export LC_ALL=C; exec 3<>/dev/tcp/127.0.0.1/1")
           :policy (read-only-sandbox-policy))))
    (test-assert (not (zerop (sandbox-result-exit-code result)))
                 "isolated networking rejects an Internet socket")
    (test-assert (search "Operation not permitted"
                         (sandbox-result-error-output result)
                         :test #'char-equal)
                 "isolated networking reports a seccomp denial"))
  nil)

(defun tests--start-proxy-server ()
  "Return a one-shot loopback proxy test socket, thread, and allocated port."
  (let ((listener
          (make-instance 'sb-bsd-sockets:inet-socket
                         :type :stream
                         :protocol :tcp)))
    (sb-bsd-sockets:socket-bind listener #(127 0 0 1) 0)
    (sb-bsd-sockets:socket-listen listener 1)
    (let ((port (nth-value 1 (sb-bsd-sockets:socket-name listener))))
      (values
       listener
       (sb-thread:make-thread
        (lambda ()
          (let* ((client (sb-bsd-sockets:socket-accept listener))
                 (stream
                   (sb-bsd-sockets:socket-make-stream
                    client
                    :input t
                    :output t
                    :element-type 'character
                    :external-format :utf-8
                    :buffering :none)))
            (unwind-protect
                 (progn
                   (write-string "pong" stream)
                   (finish-output stream))
              (close stream))))
        :name "cl-exec-sandbox proxy test server")
       port))))

(defun test-managed-proxy-network ()
  "Test proxy-only networking reaches a loopback proxy and rewrites its URL."
  (multiple-value-bind (server thread port)
      (tests--start-proxy-server)
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/bash"
                  '("-c"
                    "port=${HTTP_PROXY##*:}; exec 3<>/dev/tcp/127.0.0.1/$port; IFS= read -r -n 4 reply <&3; printf %s \"$reply\"")
                  :policy (read-only-sandbox-policy :network :proxy-only)
                  :environment
                  (list (format nil "HTTP_PROXY=http://127.0.0.1:~D" port))
                  :timeout 3)))
           (test-assert (zerop (sandbox-result-exit-code result))
                        "proxy-only command completes through the managed bridge")
           (test-assert (string= (sandbox-result-output result) "pong")
                        "managed proxy bridge carries bidirectional bytes"))
      (sb-bsd-sockets:socket-close server)
      (sb-thread:join-thread thread :default nil)))
  nil)

(defun run-tests ()
  "Run all cl-exec-sandbox tests and return true."
  (setf *test-count* 0)
  (test-executable-file-detection)
  (test-policy-validation)
  (test-bwrap-override)
  (test-seatbelt-override)
  (test-seatbelt-profile-translation)
  (test-read-only-enforcement)
  (test-workspace-write-enforcement)
  (test-missing-protected-metadata)
  (test-deny-and-nested-override)
  (test-deny-glob)
  (test-unrestricted-filesystem-with-isolated-network)
  (test-external-execution-context)
  (test-process-group-platform-support)
  (test-timeout)
  (test-direct-timeout-descendant-cleanup)
  (test-interrupted-execution-cleanup)
  (test-interrupted-launch-ownership)
  (test-merged-output)
  (test-output-capture-limits)
  (test-isolated-network-seccomp)
  (test-managed-proxy-network)
  (format t "~&~D cl-exec-sandbox tests passed.~%" *test-count*)
  t)
