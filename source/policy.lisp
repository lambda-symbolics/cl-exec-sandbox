(in-package #:cl-exec-sandbox)

;;;; -- Filesystem Rules --

(defclass filesystem-rule ()
  ((kind
    :initarg :kind
    :reader filesystem-rule-kind
    :type (member :path :glob :special)
    :documentation "Whether PATH is literal, a deny glob, or a special path token.")
   (path
    :initarg :path
    :reader filesystem-rule-path
    :type t
    :documentation "The literal pathname, glob string, or special path keyword.")
   (subpath
    :initarg :subpath
    :initform nil
    :reader filesystem-rule-subpath
    :type (or null string)
    :documentation "An optional relative suffix for a workspace-roots special rule.")
   (access
    :initarg :access
    :reader filesystem-rule-access
    :type (member :read :write :deny)
    :documentation "The effective access granted or denied at this rule."))
  (:documentation "One filesystem rule in a sandbox policy."))

(defun make-filesystem-rule (&key kind path subpath access)
  "Create and validate one filesystem rule."
  (unless (member kind '(:path :glob :special))
    (error 'sandbox-policy-error
           :message "A filesystem rule kind must be :PATH, :GLOB, or :SPECIAL."))
  (unless (member access '(:read :write :deny))
    (error 'sandbox-policy-error
           :message "A filesystem rule access must be :READ, :WRITE, or :DENY."))
  (when (and (eq kind :glob) (not (eq access :deny)))
    (error 'sandbox-policy-error
           :message "Glob filesystem rules may only deny access."))
  (ecase kind
    (:path
     (unless (or (pathnamep path) (stringp path))
       (error 'sandbox-policy-error
              :message "A literal filesystem rule requires a pathname or string.")))
    (:glob
     (unless (and (stringp path) (plusp (length path)))
       (error 'sandbox-policy-error
              :message "A glob filesystem rule requires a non-empty pattern.")))
    (:special
     (unless (member path '(:root :minimal :home :search-path :working-directory
                            :workspace-roots :tmpdir :slash-tmp))
       (error 'sandbox-policy-error
              :message "Unknown special filesystem path token."))
     (when (and subpath (not (eq path :workspace-roots)))
       (error 'sandbox-policy-error
              :message "Only :WORKSPACE-ROOTS accepts a subpath."))))
  (make-instance 'filesystem-rule
                 :kind kind
                 :path path
                 :subpath subpath
                 :access access))


;;;; -- Policy --

(defclass sandbox-policy ()
  ((filesystem-kind
    :initarg :filesystem-kind
    :reader sandbox-policy-filesystem-kind
    :type (member :restricted :unrestricted :external)
    :documentation "Whether this library enforces a restricted filesystem view.")
   (filesystem-rules
    :initarg :filesystem-rules
    :reader sandbox-policy-filesystem-rules
    :type list
    :documentation "Ordered filesystem rules resolved by specificity at launch.")
   (network
    :initarg :network
    :reader sandbox-policy-network
    :type (member :enabled :isolated :proxy-only)
    :documentation "The network namespace and syscall policy.")
   (workspace-roots
    :initarg :workspace-roots
    :reader sandbox-policy-workspace-roots
    :type list
    :documentation "Absolute project roots expanded by :WORKSPACE-ROOTS rules.")
   (glob-scan-maximum-depth
    :initarg :glob-scan-maximum-depth
    :reader sandbox-policy-glob-scan-maximum-depth
    :type (or null (integer 0))
    :documentation "The optional maximum depth for deny-glob expansion.")
   (mount-proc-p
    :initarg :mount-proc-p
    :reader sandbox-policy-mount-proc-p
    :type boolean
    :documentation "Whether a fresh procfs should be mounted in a PID namespace.")
   (isolate-processes-p
    :initarg :isolate-processes-p
    :reader sandbox-policy-isolate-processes-p
    :type boolean
    :documentation "Whether user, PID, IPC, and UTS namespaces are required.")
   (protected-metadata-names
    :initarg :protected-metadata-names
    :reader sandbox-policy-protected-metadata-names
    :type list
    :documentation "Metadata basenames kept read-only beneath writable workspace roots."))
  (:documentation "A complete process sandbox policy independent of its host backend."))

(defun policy--absolute-directory (path label)
  "Return PATH as an absolute directory pathname or signal a policy error using LABEL."
  (let ((pathname (uiop:ensure-directory-pathname (pathname path))))
    (unless (uiop:absolute-pathname-p pathname)
      (error 'sandbox-policy-error
             :message (format nil "~A must be absolute: ~A" label path)))
    pathname))

(defun make-sandbox-policy
    (&key
       (filesystem-kind :restricted)
       (filesystem-rules nil)
       (network :isolated)
       (workspace-roots nil)
       glob-scan-maximum-depth
       (mount-proc-p t)
       (isolate-processes-p t)
       (protected-metadata-names '(".git" ".agents" ".codex")))
  "Create a validated general-purpose sandbox policy."
  (unless (member filesystem-kind '(:restricted :unrestricted :external))
    (error 'sandbox-policy-error
           :message "FILESYSTEM-KIND must be :RESTRICTED, :UNRESTRICTED, or :EXTERNAL."))
  (unless (member network '(:enabled :isolated :proxy-only))
    (error 'sandbox-policy-error
           :message "NETWORK must be :ENABLED, :ISOLATED, or :PROXY-ONLY."))
  (when (and (eq filesystem-kind :external) (not (eq network :enabled)))
    (error 'sandbox-policy-error
           :message "An :EXTERNAL policy cannot request library-managed networking."))
  (unless (every (lambda (rule) (typep rule 'filesystem-rule)) filesystem-rules)
    (error 'sandbox-policy-error
           :message "FILESYSTEM-RULES must contain only FILESYSTEM-RULE instances."))
  (unless (or (null glob-scan-maximum-depth)
              (typep glob-scan-maximum-depth '(integer 0)))
    (error 'sandbox-policy-error
           :message "GLOB-SCAN-MAXIMUM-DEPTH must be NIL or a non-negative integer."))
  (unless (every (lambda (name)
                   (and (stringp name)
                        (plusp (length name))
                        (not (find #\/ name))))
                 protected-metadata-names)
    (error 'sandbox-policy-error
           :message "Protected metadata names must be non-empty path basenames."))
  (make-instance 'sandbox-policy
                 :filesystem-kind filesystem-kind
                 :filesystem-rules (copy-list filesystem-rules)
                 :network network
                 :workspace-roots
                 (mapcar (lambda (path)
                           (policy--absolute-directory path "A workspace root"))
                         workspace-roots)
                 :glob-scan-maximum-depth glob-scan-maximum-depth
                 :mount-proc-p (not (null mount-proc-p))
                 :isolate-processes-p (not (null isolate-processes-p))
                 :protected-metadata-names
                 (mapcar #'copy-seq protected-metadata-names)))

(defun policy--special-rule (path access &optional subpath)
  "Return one special PATH rule granting ACCESS and optional SUBPATH."
  (make-filesystem-rule :kind :special
                        :path path
                        :subpath subpath
                        :access access))

(defun policy--path-rule (path access)
  "Return one literal PATH rule granting ACCESS."
  (make-filesystem-rule :kind :path :path path :access access))

(defun policy--hidden-home-rules ()
  "Return rules hiding the user's home directory while keeping the executables
on the search path and the command's working directory readable."
  (list (policy--special-rule :home :deny)
        (policy--special-rule :search-path :read)
        (policy--special-rule :working-directory :read)))

(defun read-only-sandbox-policy
    (&key (network :isolated) workspace-roots (hide-home-p t))
  "Return a whole-filesystem read-only policy.

Unless HIDE-HOME-P is false, the user's home directory is hidden, apart from
workspace roots, search-path directories, and the working directory inside it,
so commands cannot read the credentials and private files kept there."
  (make-sandbox-policy
   :network network
   :workspace-roots workspace-roots
   :filesystem-rules (append (list (policy--special-rule :root :read))
                             (and hide-home-p (policy--hidden-home-rules)))))

(defun workspace-write-sandbox-policy
    (&key
       workspace-roots
       (network :isolated)
       (write-tmpdir-p t)
       (write-slash-tmp-p t)
       (hide-home-p t)
       (protected-metadata-names '(".git" ".agents" ".codex")))
  "Return a read-only host policy with writable project and temporary roots.

Unless HIDE-HOME-P is false, the user's home directory is hidden, apart from
workspace roots, search-path directories, and the working directory inside it,
so commands cannot read the credentials and private files kept there."
  (unless workspace-roots
    (error 'sandbox-policy-error
           :message "A workspace-write policy requires at least one workspace root."))
  (let ((rules (append (list (policy--special-rule :root :read))
                       (and hide-home-p (policy--hidden-home-rules))
                       (list (policy--special-rule :workspace-roots :write)))))
    (when write-slash-tmp-p
      (setf rules (append rules (list (policy--special-rule :slash-tmp :write)))))
    (when write-tmpdir-p
      (setf rules (append rules (list (policy--special-rule :tmpdir :write)))))
    (make-sandbox-policy
     :network network
     :workspace-roots workspace-roots
     :protected-metadata-names protected-metadata-names
     :filesystem-rules rules)))

(defun unrestricted-sandbox-policy (&key (network :enabled))
  "Return a policy granting full filesystem and selected network access."
  (make-sandbox-policy :filesystem-kind :unrestricted
                       :network network
                       :isolate-processes-p nil))

(defun external-sandbox-policy (&key (network :enabled))
  "Return a policy declaring that containment is supplied outside this library."
  (make-sandbox-policy :filesystem-kind :external
                       :network network
                       :isolate-processes-p nil))
