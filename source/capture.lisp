(in-package #:cl-exec-sandbox)

;;;; -- Raw capture --

(defclass sandbox-capture ()
  ((path :initarg :path :reader sandbox-capture-path
         :documentation "Private binary file, owned by the caller when retained.")
   (retained-p :initarg :retained-p :initform nil :reader sandbox-capture-retained-p
               :documentation "Whether capture ownership is transferred to the caller.")
   (byte-count :initform 0 :accessor sandbox-capture-byte-count
               :documentation "Bytes present in the closed capture file.")
   (observed-byte-count :initform 0 :accessor sandbox-capture-observed-byte-count
                        :documentation "Bytes successfully drained from the pipe.")
   (complete-p :initform nil :accessor sandbox-capture-complete-p
               :documentation "True only after EOF and successful complete storage.")
   (truncated-p :initform nil :accessor sandbox-capture-truncated-p
                :documentation "Whether drained bytes could not all be stored.")
   (status :initform ':interrupted :accessor sandbox-capture-status
           :documentation "Complete, limit, write-error, or execution interruption status."))
  (:documentation "Portable metadata for a bounded raw-byte capture."))

(defun capture--allocate (directory &key retained-p)
  "Allocate a private capture file in DIRECTORY or the temporary directory."
  #-win32
  (multiple-value-bind (descriptor name)
      (sb-posix:mkstemp
       (uiop:native-namestring
        (merge-pathnames "cl-exec-sandbox-capture-XXXXXX"
                         (merge-pathnames (or directory (uiop:temporary-directory))
                                          (uiop:getcwd)))))
    (let ((transferred-p nil))
      (unwind-protect
           (prog1 (make-instance 'sandbox-capture :path (pathname name) :retained-p retained-p)
             (setf transferred-p t))
        (sb-posix:close descriptor)
        (unless transferred-p (ignore-errors (delete-file name))))))
  #+win32
  (uiop:with-temporary-file (:pathname path :directory directory
                             :prefix "cl-exec-sandbox-capture-"
                             :element-type '(unsigned-byte 8) :keep t)
    (make-instance 'sandbox-capture :path path :retained-p retained-p)))

(defun capture--write-buffer (stream buffer count)
  "Store and flush COUNT raw bytes from BUFFER to STREAM."
  (write-sequence buffer stream :end count)
  (finish-output stream))

(defun capture--drain (stream capture limit)
  "Drain STREAM in fixed buffers, preserving pending bytes even on interruption."
  (let ((buffer (make-array 8192 :element-type '(unsigned-byte 8)))
        (count 0)
        (stored 0)
        (destination nil))
    (labels ((flush-buffer ()
               (let ((wanted (min count (- limit stored))))
                 (when (and destination (plusp wanted))
                   (handler-case
                       (progn
                         (capture--write-buffer destination buffer wanted)
                         (incf stored wanted))
                     (error ()
                       (setf (sandbox-capture-status capture) ':write-error)
                       (ignore-errors (close destination :abort t))
                       (setf destination nil))))
                 (when (< wanted count)
                   (unless (eq (sandbox-capture-status capture) ':write-error)
                     (setf (sandbox-capture-status capture) ':limit)))
                 (setf count 0))))
      (unwind-protect
           (handler-case
               (progn
                 (handler-case
                     (setf destination (open (sandbox-capture-path capture)
                                             :direction ':output :if-exists ':append
                                             :element-type '(unsigned-byte 8)))
                   (error ()
                     (setf (sandbox-capture-status capture) ':write-error)))
                 (loop for byte = (read-byte stream nil nil)
                       while byte
                       do (sb-sys:without-interrupts
                            (setf (aref buffer count) byte)
                            (incf count)
                            (incf (sandbox-capture-observed-byte-count capture))
                            (when (= count (length buffer)) (flush-buffer))))
                 (when (eq (sandbox-capture-status capture) ':interrupted)
                   (setf (sandbox-capture-status capture) ':complete)))
             (error ()
               ;; A pipe read failure is distinct from disk-write failure.
               (unless (eq (sandbox-capture-status capture) ':write-error)
                 (setf (sandbox-capture-status capture) ':interrupted))))
        (flush-buffer)
        (when destination
          (handler-case (close destination)
            (error ()
              (setf (sandbox-capture-status capture) ':write-error))))
        (ignore-errors (close stream)))))
  t)

(defun capture--finish (capture execution-status)
  "Measure the closed file and combine storage and execution status."
  (when capture
    (handler-case
        (with-open-file (stream (sandbox-capture-path capture)
                                :element-type '(unsigned-byte 8))
          (setf (sandbox-capture-byte-count capture) (file-length stream)))
      (error ()
        (setf (sandbox-capture-status capture) ':write-error)))
    (when (and (not (eq execution-status ':exited))
               (member (sandbox-capture-status capture) '(:complete :interrupted)))
      (setf (sandbox-capture-status capture) execution-status))
    (setf (sandbox-capture-truncated-p capture)
          (< (sandbox-capture-byte-count capture)
             (sandbox-capture-observed-byte-count capture))
          (sandbox-capture-complete-p capture)
          (and (eq (sandbox-capture-status capture) ':complete)
               (not (sandbox-capture-truncated-p capture)))))
  capture)

(defun sample-capture (capture &key (head-bytes 2048) (tail-bytes 2048))
  "Return bounded raw head, non-overlapping tail, and omitted retained byte count."
  (execute--validate-output-limit head-bytes "HEAD-BYTES")
  (execute--validate-output-limit tail-bytes "TAIL-BYTES")
  (unless (and head-bytes tail-bytes)
    (error 'sandbox-policy-error :message "Sample sizes must be finite."))
  (with-open-file (stream (sandbox-capture-path capture)
                          :element-type '(unsigned-byte 8))
    (let* ((size (file-length stream))
           (head-size (min size head-bytes))
           (tail-size (min (- size head-size) tail-bytes))
           (head (make-array head-size :element-type '(unsigned-byte 8)))
           (tail (make-array tail-size :element-type '(unsigned-byte 8))))
      (read-sequence head stream)
      (file-position stream (- size tail-size))
      (read-sequence tail stream)
      (values head tail (- size head-size tail-size)))))

(defun decode-capture-bytes (octets)
  "Decode raw OCTETS as UTF-8, replacing malformed sequences only for display."
  (sb-ext:octets-to-string octets :external-format '(:utf-8 :replacement #\Replacement_Character)))

(defun capture--read-prefix (capture limit)
  "Return a tolerant text prefix and a separate inline truncation flag."
  (with-open-file (stream (sandbox-capture-path capture)
                          :element-type '(unsigned-byte 8))
    (let* ((size (file-length stream))
           ;; UTF-8 needs at most four bytes per character. Allocation is bounded
           ;; when a legacy character limit was supplied.
           (count (if limit (min size (* 4 (1+ limit))) size))
           (bytes (make-array count :element-type '(unsigned-byte 8)))
           (read-count (read-sequence bytes stream))
           (text (decode-capture-bytes (subseq bytes 0 read-count))))
      (values (if limit (subseq text 0 (min limit (length text))) text)
              (or (< read-count size) (and limit (> (length text) limit)))))))
