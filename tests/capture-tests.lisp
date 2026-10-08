(in-package #:cl-exec-sandbox/tests)

;;;; -- Retained binary capture --

(defun capture-tests--bytes (path)
  "Read the small fixture at PATH as raw bytes."
  (with-open-file (stream path :element-type '(unsigned-byte 8))
    (let ((bytes (make-array (file-length stream) :element-type '(unsigned-byte 8))))
      (read-sequence bytes stream)
      bytes)))

(defun test-retained-byte-capture ()
  "Test exact large output, bounded sampling, invalid UTF-8 and separate streams."
  (let* ((root (tests--temporary-root))
         (fixture (merge-pathnames "bytes" root))
         (bytes (make-array 131073 :element-type '(unsigned-byte 8)))
         (callback-count 0))
    (dotimes (index (length bytes))
      (setf (aref bytes index) (mod index 256)))
    (unwind-protect
         (progn
           (with-open-file (stream fixture :direction ':output
                                   :element-type '(unsigned-byte 8)
                                   :if-does-not-exist ':create)
             (write-sequence bytes stream))
           (let* ((result (run-sandboxed "/bin/cat" (list (namestring fixture))
                                         :policy (unrestricted-sandbox-policy)
                                         :capture-directory root :output-limit 11
                                         :capture-function (lambda (result)
                                                             (declare (ignore result))
                                                             (incf callback-count))))
                  (capture (sandbox-result-output-capture result)))
             (test-assert (equalp bytes (capture-tests--bytes (sandbox-capture-path capture)))
                          "large retained bytes are exact, including NUL and malformed UTF-8")
             (test-assert (= (sandbox-capture-byte-count capture) (length bytes))
                          "capture byte count reflects raw file size")
             (test-assert (= (sandbox-capture-observed-byte-count capture) (length bytes))
                          "observed count reflects exactly drained bytes")
             (test-assert (sandbox-capture-complete-p capture) "ordinary EOF is complete")
             (test-assert (sandbox-result-output-truncated-p result)
                          "inline truncation is independent of capture completeness")
             (test-assert (= (length (sandbox-result-output result)) 11)
                          "legacy inline character limit is honored")
             (multiple-value-bind (head tail omitted)
                 (sample-capture capture :head-bytes 17 :tail-bytes 19)
               (test-assert (equalp head (subseq bytes 0 17)) "head sample is exact")
               (test-assert (equalp tail (subseq bytes (- (length bytes) 19)))
                            "tail sample is exact")
               (test-assert (= omitted (- (length bytes) 36)) "sampling reports omissions"))
             (test-assert (find #\Replacement_Character (decode-capture-bytes bytes))
                          "invalid UTF-8 renders replacement characters without changing raw bytes")
             #-win32
             (test-assert (= #o600 (logand #o777 (sb-posix:stat-mode
                                                (sb-posix:stat (namestring
                                                               (sandbox-capture-path capture))))))
                          "capture files have private permissions"))
           (test-assert (= callback-count 1) "normal callback runs exactly once")
           (dolist (merged '(nil t))
             (let* ((result (run-sandboxed "/bin/sh"
                                          '("-c" "printf out; printf diagnostic >&2; exit 7")
                                          :policy (unrestricted-sandbox-policy)
                                          :capture-directory root :merge-output-p merged
                                          :output-limit 20 :error-output-limit 20))
                    (output (sandbox-result-output-capture result))
                    (error (sandbox-result-error-capture result)))
               (test-assert (= (sandbox-result-exit-code result) 7)
                            "nonzero exit status is retained")
               (test-assert (sandbox-capture-complete-p output)
                            "failed commands can have complete captures")
               (test-assert (string= (decode-capture-bytes
                                     (capture-tests--bytes (sandbox-capture-path output)))
                                    (if merged "outdiagnostic" "out"))
                            "merged and separate output preserve raw bytes")
               (test-assert (if merged (null error)
                               (and (sandbox-capture-complete-p error)
                                    (string= (sandbox-result-error-output result) "diagnostic")))
                            "separate metadata never claims merged interleaving")))
           (let* ((result (run-sandboxed "/bin/sh" '("-c" "printf abcd")
                                        :policy (unrestricted-sandbox-policy)
                                        :retain-output-p t))
                  (capture (sandbox-result-output-capture result)))
             (unwind-protect
                  (multiple-value-bind (head tail omitted)
                      (sample-capture capture :head-bytes 3 :tail-bytes 3)
                    (test-assert (= (+ (length head) (length tail)) 4)
                                 "small samples do not overlap")
                    (test-assert (zerop omitted) "small capture has no omitted bytes"))
               (delete-file (sandbox-capture-path capture))
               (delete-file (sandbox-capture-path (sandbox-result-error-capture result))))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-retained-capture-limits ()
  "Test an enforced per-stream disk maximum while all excess bytes are drained."
  (let ((root (tests--temporary-root)))
    (unwind-protect
         (dolist (limit '(0 5 10000))
           (let* ((result (run-sandboxed "/bin/sh"
                                        '("-c" "i=0; while [ $i -lt 1000 ]; do printf 0123456789; printf abcdefghij >&2; i=$((i+1)); done")
                                        :policy (unrestricted-sandbox-policy)
                                        :capture-directory root :capture-byte-limit limit
                                        :output-limit 0 :error-output-limit 0))
                  (captures (list (sandbox-result-output-capture result)
                                  (sandbox-result-error-capture result))))
             (test-assert (zerop (sandbox-result-exit-code result))
                          "discarded excess output never blocks the child")
             (dolist (capture captures)
               (test-assert (= (sandbox-capture-byte-count capture) limit)
                            "disk maximum is enforced exactly")
               (test-assert (= (sandbox-capture-observed-byte-count capture) 10000)
                            "only actually drained bytes count as observed")
               (test-assert (eq (sandbox-capture-status capture)
                                (if (= limit 10000) ':complete ':limit))
                            "limit status is truthful at exact boundary")
               (test-assert (eq (sandbox-capture-complete-p capture) (= limit 10000))
                            "capture completeness distinguishes inline and disk limits"))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-retained-capture-unwinds ()
  "Test timeout, predicate and nonlocal cancellation with final callbacks."
  (let ((root (tests--temporary-root)))
    (unwind-protect
         (dolist (mode '(:timeout :cancelled :interrupted))
           (let ((callback-result nil)
                 (polls 0))
             (catch 'capture-interrupt
               (run-sandboxed "/bin/sh" '("-c" "printf beginning; sleep 5")
                              :policy (unrestricted-sandbox-policy)
                              :capture-directory root :merge-output-p t
                              :timeout (when (eq mode ':timeout) 0.1)
                              :cancel-function
                              (unless (eq mode ':timeout)
                                (lambda ()
                                  (when (> (incf polls) 10)
                                    (if (eq mode ':interrupted)
                                        (throw 'capture-interrupt t)
                                        t))))
                              :capture-function (lambda (result) (setf callback-result result))))
             (test-assert callback-result "each unwind publishes final capture metadata")
             (test-assert (eq (sandbox-result-status callback-result) mode)
                          "execution status distinguishes each interruption")
             (let ((capture (sandbox-result-output-capture callback-result)))
               (test-assert (not (sandbox-capture-complete-p capture))
                            "interrupted command output is never marked complete")
               (test-assert (string= "beginning"
                                    (decode-capture-bytes
                                     (capture-tests--bytes (sandbox-capture-path capture))))
                            "pending short output survives every unwind"))
             (test-assert (< (sandbox-result-real-seconds callback-result) 2)
                          "termination and capture shutdown are bounded")))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-retained-capture-launch-failure ()
  "Test failed native launch preserves empty files and final callback metadata."
  (let ((root (tests--temporary-root))
        (original (symbol-function 'cl-exec-sandbox::execute--launch-plan))
        (callback-result nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'cl-exec-sandbox::execute--launch-plan)
                 (lambda (&rest arguments)
                   (declare (ignore arguments))
                   (error 'file-error :pathname #P"missing-program")))
           (handler-case
               (run-sandboxed "/bin/sh" '("-c" "exit 0")
                              :policy (unrestricted-sandbox-policy)
                              :capture-directory root
                              :capture-function (lambda (result) (setf callback-result result)))
             (sandbox-execution-error (condition)
               (test-assert (eq callback-result (sandbox-execution-error-result condition))
                            "launch failure condition exposes the final result")))
           (test-assert (eq (sandbox-result-status callback-result) ':launch-failed)
                        "launch failure has its own execution status")
           (dolist (capture (list (sandbox-result-output-capture callback-result)
                                 (sandbox-result-error-capture callback-result)))
             (test-assert (and (probe-file (sandbox-capture-path capture))
                               (zerop (sandbox-capture-byte-count capture))
                               (not (sandbox-capture-complete-p capture)))
                          "launch failure retains truthful empty captures")))
      (setf (symbol-function 'cl-exec-sandbox::execute--launch-plan) original)
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-retained-capture-held-pipe ()
  "Test a descendant retaining a pipe cannot deadlock output-reader shutdown."
  (let* ((root (tests--temporary-root))
         (previous (uiop:getenv "CL_EXEC_SANDBOX_PROCESS_GROUP_HELPER")))
    (unwind-protect
         (progn
           ;; Exercise the documented direct-process fallback, whose descendants
           ;; cannot be terminated through a process group.
           (sb-posix:setenv "CL_EXEC_SANDBOX_PROCESS_GROUP_HELPER" "/missing/helper" 1)
           (let* ((result (run-sandboxed "/bin/sh"
                                        '("-c" "printf beginning; sleep 2 & exit 0")
                                        :policy (unrestricted-sandbox-policy)
                                        :capture-directory root :merge-output-p t :output-limit 20))
                  (capture (sandbox-result-output-capture result)))
             (test-assert (< (sandbox-result-real-seconds result) 1.5)
                          "held pipes have bounded reader shutdown")
             (test-assert (eq (sandbox-capture-status capture) ':interrupted)
                          "held-pipe capture is explicitly incomplete")
             (test-assert (string= (sandbox-result-output result) "beginning")
                          "held-pipe shutdown flushes pending bytes")))
      (if previous
          (sb-posix:setenv "CL_EXEC_SANDBOX_PROCESS_GROUP_HELPER" previous 1)
          (sb-posix:unsetenv "CL_EXEC_SANDBOX_PROCESS_GROUP_HELPER"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-retained-capture-write-failure ()
  "Test disk-full writes before and after a retained prefix, without blocking the child."
  (let ((root (tests--temporary-root))
        (original (symbol-function 'cl-exec-sandbox::capture--write-buffer)))
    (unwind-protect
         (dolist (successful-buffers '(0 1))
           (let ((attempts 0))
             (setf (symbol-function 'cl-exec-sandbox::capture--write-buffer)
                   (lambda (stream buffer count)
                     (cond
                       ((<= (incf attempts) successful-buffers)
                        (funcall original stream buffer count))
                       ((probe-file #P"/dev/full")
                        ;; Real ENOSPC at the file-write boundary on POSIX hosts.
                        (with-open-file (full #P"/dev/full" :direction ':output
                                              :if-exists ':append
                                              :element-type '(unsigned-byte 8))
                          (funcall original full buffer count)))
                       (t
                        (error 'file-error :pathname root)))))
             (let* ((result (run-sandboxed "/bin/sh"
                                          '("-c" "i=0; while [ $i -lt 1000 ]; do printf 0123456789; i=$((i+1)); done")
                                          :policy (unrestricted-sandbox-policy)
                                          :capture-directory root :merge-output-p t))
                    (capture (sandbox-result-output-capture result)))
               (test-assert (zerop (sandbox-result-exit-code result))
                            "disk-full capture continues draining the child")
               (test-assert (= (sandbox-capture-observed-byte-count capture) 10000)
                            "failed storage counts only drained output")
               (test-assert (and (eq (sandbox-capture-status capture) ':write-error)
                                 (= (sandbox-capture-byte-count capture) (* 8192 successful-buffers))
                                 (not (sandbox-capture-complete-p capture))
                                 (sandbox-capture-truncated-p capture))
                            "disk-full metadata measures the actually retained prefix"))))
      (setf (symbol-function 'cl-exec-sandbox::capture--write-buffer) original)
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-retained-capture-creation ()
  "Test pre-launch identity publication and callback failure without side effects."
  (let* ((root (tests--temporary-root))
         (sentinel (merge-pathnames "launched" root)))
    (unwind-protect
         (dolist (fail-p '(nil t))
           (let ((initial nil)
                 (final nil)
                 (created-count 0)
                 (final-count 0))
             (handler-case
                 (run-sandboxed "/bin/sh"
                                (list "-c" (format nil "printf launched > ~A; printf hello"
                                                   (uiop:escape-shell-token (namestring sentinel))))
                                :policy (unrestricted-sandbox-policy)
                                :capture-directory root
                                :capture-created-function
                                (lambda (result)
                                  (incf created-count)
                                  (setf initial result)
                                  (test-assert (not (probe-file sentinel))
                                               "initial identity callback precedes side effects")
                                  (dolist (capture (list (sandbox-result-output-capture result)
                                                        (sandbox-result-error-capture result)))
                                    (test-assert (and (probe-file (sandbox-capture-path capture))
                                                      (zerop (sandbox-capture-byte-count capture))
                                                      (not (sandbox-capture-complete-p capture)))
                                                 "initial files exist with incomplete zero-byte metadata"))
                                  (when fail-p (error 'file-error :pathname root)))
                                :capture-function (lambda (result)
                                                    (incf final-count)
                                                    (setf final result)))
               (sandbox-execution-error ()
                 (test-assert fail-p "only failed creation callback prevents launch")))
             (test-assert (and (= created-count 1) (= final-count 1))
                          "creation and final callbacks each occur once")
             (test-assert (equal (sandbox-capture-path (sandbox-result-output-capture initial))
                                 (sandbox-capture-path (sandbox-result-output-capture final)))
                          "published capture identity matches final identity")
             (test-assert (eq (sandbox-result-status final)
                              (if fail-p ':launch-failed ':exited))
                          "creation callback failure returns final launch-failed metadata")
             (test-assert (eq (not (null (probe-file sentinel))) (not fail-p))
                          "creation callback failure prevents native side effects")
             (when (probe-file sentinel) (delete-file sentinel))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-transient-capture-cleanup ()
  "Test legacy transient ownership and cleanup when the final callback unwinds."
  (dolist (unwind-p '(nil t))
    (let ((final nil))
      (catch 'capture-final-unwind
        (run-sandboxed "/bin/sh" '("-c" "printf short")
                       :policy (unrestricted-sandbox-policy)
                       :capture-function
                       (lambda (result)
                         (setf final result)
                         (test-assert (probe-file (sandbox-capture-path
                                                  (sandbox-result-output-capture result)))
                                      "final callback can inspect the closed transient file")
                         (when unwind-p (throw 'capture-final-unwind t)))))
      (dolist (capture (list (sandbox-result-output-capture final)
                            (sandbox-result-error-capture final)))
        (test-assert (not (sandbox-capture-retained-p capture))
                     "legacy transient captures do not transfer ownership")
        (test-assert (not (probe-file (sandbox-capture-path capture)))
                     "transient files are removed even when final callback unwinds"))))
  nil)

(defun capture-tests--wait-for (predicate)
  "Wait at most two seconds for a coordinated test boundary."
  (loop repeat 200
        when (funcall predicate) return t
        do (sleep 0.01)
        finally (return nil)))

(defun test-retained-capture-repeated-interrupt ()
  "Test a second asynchronous nonlocal cancellation cannot abandon cleanup."
  (let* ((root (tests--temporary-root))
         (started (merge-pathnames "started" root))
         (finished (merge-pathnames "finished" root))
         (original (symbol-function 'cl-exec-sandbox::execute--join-reader))
         (worker nil)
         (cleanup-entered-p nil)
         (supervising-p nil)
         (release-p nil)
         (second-delivered-p nil)
         (second-before-callback-p nil)
         (callback-count 0)
         (final nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'cl-exec-sandbox::execute--join-reader)
                 (lambda (thread capture)
                   (setf cleanup-entered-p t)
                   (loop repeat 500 until release-p do (sleep 0.01))
                   (funcall original thread capture)))
           (setf worker
                 (sb-thread:make-thread
                  (lambda ()
                    (catch 'capture-async-stop
                      (run-sandboxed
                       "/bin/sh"
                       (list "-c" (format nil
                                          "printf beginning; printf started > ~A; (sleep 0.3; printf leaked > ~A) & wait"
                                          (uiop:escape-shell-token (namestring started))
                                          (uiop:escape-shell-token (namestring finished))))
                       :policy (unrestricted-sandbox-policy)
                       :capture-directory root :merge-output-p t
                       :cancel-function (lambda () (setf supervising-p t) nil)
                       :capture-function (lambda (result)
                                           (incf callback-count)
                                           (setf final result))))
                    t)
                  :name "retained capture repeated interruption"))
           (test-assert (capture-tests--wait-for
                         (lambda () (and supervising-p (probe-file started))))
                        "asynchronously cancelled command reaches active supervision")
           (sb-thread:interrupt-thread worker (lambda () (throw 'capture-async-stop ':first)))
           (test-assert (capture-tests--wait-for (lambda () cleanup-entered-p))
                        "first cancellation enters ordered cleanup")
           (sb-thread:interrupt-thread worker
                                       (lambda ()
                                         (setf second-delivered-p t
                                               second-before-callback-p (null final))
                                         (throw 'capture-async-stop ':second)))
           (sleep 0.05)
           (test-assert (not second-delivered-p)
                        "second cancellation is deferred during cleanup")
           (setf release-p t)
           (test-assert (sb-thread:join-thread worker :timeout 3 :default nil)
                        "repeated cancellation completes within bounded cleanup time")
           (test-assert (and second-delivered-p (not second-before-callback-p)
                             (= callback-count 1))
                        "final metadata callback precedes deferred cancellation exactly once")
           (let ((capture (sandbox-result-output-capture final)))
             (test-assert (and (= (sandbox-capture-byte-count capture) 9)
                               (eq (sandbox-capture-status capture) ':interrupted)
                               (string= "beginning"
                                        (decode-capture-bytes
                                         (capture-tests--bytes (sandbox-capture-path capture)))))
                          "repeated interruption retains closed pending output truthfully"))
           (sleep 0.4)
           (test-assert (not (probe-file finished))
                        "repeated cancellation cannot abandon descendant termination"))
      (setf release-p t)
      (when (and worker (sb-thread:thread-alive-p worker))
        (ignore-errors
          (sb-thread:interrupt-thread worker (lambda () (throw 'capture-async-stop ':cleanup))))
        (ignore-errors (sb-thread:join-thread worker :timeout 3 :default nil)))
      (setf (symbol-function 'cl-exec-sandbox::execute--join-reader) original)
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-capture-rendering-defaults ()
  "Test retained mode avoids whole-log rendering while legacy text capture is available."
  (let ((root (tests--temporary-root)))
    (unwind-protect
         (progn
           (let* ((result (run-sandboxed "/bin/sh" '("-c" "printf out; printf err >&2")
                                        :policy (unrestricted-sandbox-policy)
                                        :capture-directory root))
                  (capture (sandbox-result-output-capture result)))
             (test-assert (and (string= (sandbox-result-output result) "")
                               (string= (sandbox-result-error-output result) "")
                               (sandbox-result-output-truncated-p result)
                               (sandbox-capture-complete-p capture)
                               (sandbox-capture-retained-p capture))
                          "retained default suppresses inline text without truncating raw capture"))
           (dolist (retained-p '(nil t))
             (let ((result (if retained-p
                               (run-sandboxed "/bin/sh" '("-c" "printf hello")
                                              :policy (unrestricted-sandbox-policy)
                                              :capture-directory root :output-limit nil)
                               (run-sandboxed "/bin/sh" '("-c" "printf hello")
                                              :policy (unrestricted-sandbox-policy)))))
               (test-assert (string= (sandbox-result-output result) "hello")
                            "legacy transient or explicit NIL renders complete text"))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun test-retained-cooperative-cancellation (&optional (repetitions 20))
  "Early cooperative cancellation reaps commands and closes both capture modes."
  (let ((root (tests--temporary-root)))
    (unwind-protect
         (dotimes (iteration repetitions)
           (let ((created (sb-thread:make-semaphore))
                 (cancelled-p nil)
                 (merged-p (evenp iteration))
                 (callback-count 0)
                 (final nil)
                 (worker nil))
             (unwind-protect
                  (progn
                    (setf worker
                          (sb-thread:make-thread
                           (lambda ()
                             (run-sandboxed "/bin/sh" '("-c" "printf started; sleep 30")
                                            :policy (unrestricted-sandbox-policy)
                                            :capture-directory root :merge-output-p merged-p
                                            :output-limit 0 :error-output-limit 0
                                            :capture-created-function
                                            (lambda (result)
                                              (declare (ignore result))
                                              (sb-thread:signal-semaphore created))
                                            :cancel-function (lambda () cancelled-p)
                                            :capture-function
                                            (lambda (result)
                                              (incf callback-count)
                                              (setf final result))))
                           :name "cooperative retained cancellation"))
                    (test-assert (sb-thread:wait-on-semaphore created :timeout 2)
                                 "prelaunch captures are published before cancellation")
                    (setf cancelled-p t)
                    (test-assert (sb-thread:join-thread worker :timeout 2 :default nil)
                                 "early cancellation terminates within bounded cleanup time")
                    (test-assert (and final (= callback-count 1)
                                      (sandbox-result-cancelled-p final)
                                      (integerp (sandbox-result-exit-code final)))
                                 "cancellation publishes one final result after native exit")
                    (dolist (capture (remove nil (list (sandbox-result-output-capture final)
                                                      (sandbox-result-error-capture final))))
                      (test-assert (and (eq (sandbox-capture-status capture) ':cancelled)
                                        (not (sandbox-capture-complete-p capture))
                                        (= (sandbox-capture-byte-count capture)
                                           (length (capture-tests--bytes
                                                    (sandbox-capture-path capture)))))
                                   "cancelled capture metadata describes the closed retained file")))
               (setf cancelled-p t)
               (when (and worker (sb-thread:thread-alive-p worker))
                 (ignore-errors (sb-thread:terminate-thread worker))
                 (ignore-errors (sb-thread:join-thread worker :timeout 2 :default nil))))))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist ':ignore)))
  nil)

(defun run-capture-tests ()
  "Run the retained raw-byte capture contracts."
  (test-retained-byte-capture)
  (test-retained-capture-limits)
  (test-retained-capture-unwinds)
  (test-retained-capture-launch-failure)
  (test-retained-capture-held-pipe)
  (test-retained-capture-write-failure)
  (test-retained-capture-creation)
  (test-transient-capture-cleanup)
  (test-retained-capture-repeated-interrupt)
  (test-retained-cooperative-cancellation)
  (test-capture-rendering-defaults)
  t)
