(in-package #:cl-exec-sandbox)

;;;; -- Host Path Helpers --

(defun path--directory-separators ()
  "Return the characters separating directory components in native namestrings."
  #+win32 '(#\/ #\\)
  #-win32 '(#\/))

(defun path--components (path)
  "Return PATH's non-empty separator-delimited components."
  (remove-if (lambda (component) (zerop (length component)))
             (uiop:split-string (uiop:native-namestring path)
                                :separator (path--directory-separators))))

(defun path--under-p (path root)
  "Return true when absolute PATH is ROOT or a descendant of ROOT."
  (let ((path-namestring (uiop:native-namestring path))
        (root-namestring
          (uiop:native-namestring (uiop:ensure-directory-pathname root))))
    (or (string= path-namestring
                 (string-right-trim (path--directory-separators) root-namestring))
        (uiop:string-prefix-p root-namestring path-namestring))))

(defun path--absolute (path cwd)
  "Resolve PATH against CWD without requiring it to exist."
  (uiop:ensure-absolute-pathname (pathname path) cwd))

(defun path--canonical (path)
  "Return absolute PATH with symbolic links resolved in its longest existing
prefix, keeping any missing trailing components and whether PATH names a
directory.

Seatbelt matches the resolved path of every file operation, so a rule naming
a link such as macOS's /tmp or /var never applies unless it is resolved first.
Windows leaves links unresolved in TRUENAME, so there PATH is returned as is."
  #+win32
  path
  #-win32
  (let ((components (path--components path)))
    (loop for count from (length components) downto 0
          for existing = (probe-file (format nil "/~{~A~^/~}"
                                             (subseq components 0 count)))
          when existing
            return (let ((resolved
                           (format nil "~A~{/~A~}"
                                   (string-right-trim
                                    "/" (uiop:native-namestring existing))
                                   (nthcdr count components))))
                     (uiop:parse-native-namestring
                      (if (zerop (length resolved)) "/" resolved)
                      :ensure-directory (null (pathname-name (pathname path))))))))

(defun path--safe-relative-subpath (subpath)
  "Return SUBPATH as a relative pathname or signal a policy error."
  (let ((pathname (pathname subpath)))
    (when (or (uiop:absolute-pathname-p pathname)
              (member :up (pathname-directory pathname)))
      (error 'sandbox-policy-error
             :message (format nil "Workspace subpath must stay relative: ~A" subpath)))
    pathname))

(defun path--executable-extensions ()
  "Return the lowercase file extensions Windows treats as executable."
  (remove "" (mapcar #'string-downcase
                     (uiop:split-string (or (uiop:getenv "PATHEXT")
                                            ".COM;.EXE;.BAT;.CMD")
                                        :separator '(#\;)))
          :test #'string=))

(defun path--executable-file-p (path)
  "Return true when PATH names an executable regular file.

POSIX consults the execute permission. Windows has no such bit, so a regular
file whose name carries one of the PATHEXT extensions counts as executable."
  (let ((native-path (uiop:native-namestring path)))
    (handler-case
        (let ((mode (sb-posix:stat-mode (sb-posix:stat native-path))))
          (and (sb-posix:s-isreg mode)
               #-win32
               (zerop (sb-posix:access native-path sb-posix:x-ok))
               #+win32
               (let ((lowercase (string-downcase native-path)))
                 (and (some (lambda (extension)
                              (uiop:string-suffix-p lowercase extension))
                            (path--executable-extensions))
                      t))))
      (sb-posix:syscall-error ()
        nil))))

(defun path--executable-candidates (pathname directory)
  "Return the pathnames under DIRECTORY that may satisfy program PATHNAME.

Windows commands are usually named without their extension, so there each
PATHEXT extension is tried after the exact name."
  (let ((exact (merge-pathnames pathname directory)))
    #-win32
    (list exact)
    #+win32
    (cons exact
          (if (pathname-type pathname)
              nil
              (loop for extension in (path--executable-extensions)
                    collect (merge-pathnames
                             (make-pathname :name (pathname-name pathname)
                                            :type (subseq extension 1))
                             directory))))))

(defun path--directories ()
  "Return PATH entries as absolute directory pathnames."
  (loop for entry in (uiop:split-string (or (uiop:getenv "PATH") "")
                                        :separator #+win32 '(#\;) #-win32 '(#\:))
        when (plusp (length entry))
          collect (uiop:ensure-directory-pathname
                   (uiop:ensure-absolute-pathname entry (uiop:getcwd)))))
