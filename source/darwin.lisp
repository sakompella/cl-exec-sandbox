(in-package #:cl-exec-sandbox)

;;;; -- macOS Seatbelt backend --

(defparameter +darwin-platform-read-roots+
  '(#P"/bin/" #P"/sbin/" #P"/usr/" #P"/System/" #P"/Library/"
    #P"/private/")
  "System directories needed by ordinary macOS command interpreters.")

(defun darwin--seatbelt-executable ()
  "Return the trusted system Seatbelt executable, or NIL."
  (when (and (probe-file #P"/usr/bin/sandbox-exec")
             (linux--executable-file-p #P"/usr/bin/sandbox-exec"))
    #P"/usr/bin/sandbox-exec"))

(defun darwin--normalize-path (value)
  "Canonicalize VALUE as far as the existing filesystem permits.

The final component may not exist, so canonicalize its deepest existing parent
and append the missing suffix.  This is needed for macOS aliases such as
/var, whose Seatbelt-visible spelling is /private/var."
  (let* ((path (uiop:ensure-absolute-pathname (pathname value) (uiop:getcwd)))
         (existing (probe-file path)))
    (or (and existing (truename existing))
        (let ((namestring (uiop:native-namestring path)))
          (labels ((find-parent (slash)
                     (when slash
                       (let* ((prefix (subseq namestring 0 slash))
                              (suffix (subseq namestring slash))
                              (parent (probe-file prefix)))
                         (or (and parent
                                  (pathname
                                   (concatenate
                                    'string
                                    (string-right-trim
                                     "/"
                                     (uiop:native-namestring
                                      (truename parent)))
                                    suffix)))
                             (find-parent
                              (and (plusp slash)
                                   (position #\/ namestring
                                             :start 1 :end slash
                                             :from-end t))))))))
            (or (find-parent
                 (position #\/ namestring :start 1 :from-end t))
                path))))))

(defun darwin--sbpl-string (value)
  "Quote VALUE as an SBPL string literal after path canonicalization."
  (let ((namestring (uiop:native-namestring (darwin--normalize-path value))))
    (with-output-to-string (stream)
      (write-char #\" stream)
      (loop for character across namestring do
        (when (member character '(#\\ #\"))
          (write-char #\\ stream))
        (write-char character stream))
      (write-char #\" stream))))

(defun darwin--regex-string (value)
  "Quote VALUE as an SBPL regex string, escaping regex backslashes."
  (with-output-to-string (stream)
    (write-char #\" stream)
    (loop for character across value do
      (when (member character '(#\\ #\"))
        (write-char #\\ stream))
      (write-char character stream))
    (write-char #\" stream)))

(defun darwin--regex-escape (value)
  "Escape VALUE for a regular expression outside a character class."
  (with-output-to-string (stream)
    (loop for character across value do
      (when (find character "\\.+()[]{}^$|*?")
        (write-char #\\ stream))
      (write-char character stream))))

(defun darwin--glob-body (pattern)
  "Return a regex body and whether PATTERN contained glob syntax.

This is the git-style subset used by the Linux deny-glob implementation:
asterisk and question mark stay within one path component, **/ crosses
components, and character classes are retained."
  (let ((saw-glob nil))
    (values
     (with-output-to-string (stream)
       (let ((length (length pattern))
             (index 0))
      (labels ((write-literal (character)
                 (when (find character "\\.+()[]{}^$|*")
                   (write-char #\\ stream))
                 (write-char character stream)))
        (loop while (< index length) do
          (let ((character (char pattern index)))
            (case character
              (#\*
               (setf saw-glob t)
               (if (and (< (1+ index) length)
                        (char= (char pattern (1+ index)) #\*))
                   (progn
                     (incf index)
                     (if (and (< (1+ index) length)
                              (char= (char pattern (1+ index)) #\/))
                         (progn
                           (incf index)
                           (write-string "(.*/)?" stream))
                         (write-string ".*" stream)))
                   (write-string "[^/]*" stream)))
              (#\?
               (setf saw-glob t)
               (write-string "[^/]" stream))
              (#\[
               (let ((close (position #\] pattern :start (1+ index))))
                 (if (null close)
                     (write-literal character)
                     (progn
                       (setf saw-glob t)
                       (write-char #\[ stream)
                       (let ((first t))
                         (loop for class-index from (1+ index) below close
                               for class-character = (char pattern class-index) do
                                 (when (and first (char= class-character #\!))
                                   (write-char #\^ stream))
                                 (unless (and first (char= class-character #\!))
                                   (when (and first (char= class-character #\^))
                                     (write-char #\\ stream))
                                   (when (char= class-character #\\)
                                     (write-char #\\ stream))
                                   (write-char class-character stream))
                                 (setf first nil))
                       (write-char #\] stream)
                       (setf index close))))))
              (#\]
               (setf saw-glob t)
               (write-string "\\]" stream))
              (otherwise
               (write-literal character)))
            (incf index)))
      )))
     saw-glob)))

(defun darwin--canonicalize-glob-prefix (pattern)
  "Canonicalize the static directory prefix of absolute PATTERN."
  (let ((first-glob
          (loop for character across pattern
                for index from 0
                when (find character "*?[]")
                  return index)))
    (if (null first-glob)
        (uiop:native-namestring (darwin--normalize-path pattern))
        (let* ((static (subseq pattern 0 first-glob))
               (slash (position #\/ static :from-end t)))
          (if (null slash)
              pattern
              (let* ((directory (subseq static 0 slash))
                     (suffix (subseq pattern slash))
                     (canonical (uiop:native-namestring
                                 (darwin--normalize-path directory))))
                (concatenate 'string
                             (string-right-trim "/" canonical)
                             suffix)))))))

(defun darwin--glob-regex (pattern root)
  "Translate PATTERN below ROOT into an anchored Seatbelt regex."
  (let* ((root (uiop:native-namestring (darwin--normalize-path root)))
         (absolute (uiop:absolute-pathname-p (pathname pattern)))
         (raw (if absolute
                  (darwin--canonicalize-glob-prefix
                   (uiop:native-namestring (pathname pattern)))
                  pattern)))
    (multiple-value-bind (body saw-glob)
        (darwin--glob-body raw)
      (let ((prefix (if absolute
                        ""
                        (concatenate 'string
                                     (string-right-trim "/" root)
                                     "/")))
            (anywhere (and (not absolute)
                           (null (position #\/ raw)))))
        (format nil "^~A~A~A~A$"
                (darwin--regex-escape prefix)
                (if anywhere "(.*/)?" "")
                body
                (if saw-glob "" "(/.*)?"))))))

(defstruct (darwin--resolved-rule
            (:constructor darwin--make-resolved-rule (matcher access)))
  "One absolute or regex rule used to construct filtered Seatbelt allows."
  matcher
  (access :read :type (member :read :write :deny)))

(defun darwin--subpath-matcher (path)
  (list :subpath (darwin--normalize-path path)))

(defun darwin--regex-matcher (regex)
  (list :regex regex))

(defun darwin--matcher-kind (matcher)
  (first matcher))

(defun darwin--matcher-value (matcher)
  (second matcher))

(defun darwin--special-paths (rule policy cwd)
  "Expand a Darwin special path rule without using Linux platform roots."
  (case (filesystem-rule-path rule)
    (:root (list #P"/"))
    (:minimal (remove-if-not #'probe-file +darwin-platform-read-roots+))
    (:workspace-roots
     (let ((subpath (and (filesystem-rule-subpath rule)
                         (linux--safe-relative-subpath
                          (filesystem-rule-subpath rule)))))
       (mapcar (lambda (root)
                 (if subpath
                     (merge-pathnames subpath root)
                     root))
               (sandbox-policy-workspace-roots policy))))
    (:tmpdir
     (list (linux--absolute-path
            (or (uiop:getenv "TMPDIR") (uiop:temporary-directory)) cwd)))
    (:slash-tmp (list #P"/tmp/"))))

(defun darwin--resolve-rules (policy cwd)
  "Resolve POLICY's literal, special, and deny-glob rules for Darwin."
  (loop for rule in (sandbox-policy-filesystem-rules policy)
        append
        (case (filesystem-rule-kind rule)
          (:path
           (list (darwin--make-resolved-rule
                  (darwin--subpath-matcher
                   (linux--absolute-path (filesystem-rule-path rule) cwd))
                  (filesystem-rule-access rule))))
          (:special
           (loop for path in (darwin--special-paths rule policy cwd)
                 collect (darwin--make-resolved-rule
                          (darwin--subpath-matcher path)
                          (filesystem-rule-access rule))))
          (:glob
           (loop for root in (or (sandbox-policy-workspace-roots policy)
                                 (list cwd))
                 collect (darwin--make-resolved-rule
                          (darwin--regex-matcher
                           (darwin--glob-regex
                            (filesystem-rule-path rule) root))
                          :deny))))))

(defun darwin--access-grants (access operation)
  "Return whether ACCESS grants the requested file OPERATION."
  (or (and (eq operation :read)
           (member access '(:read :write)))
      (and (eq operation :write)
           (eq access :write))))

(defun darwin--path-under-p (path root)
  "Return true when PATH is ROOT or a descendant of ROOT."
  (linux--path-under-p (darwin--normalize-path path)
                       (darwin--normalize-path root)))

(defun darwin--matcher-under-root-p (matcher root)
  "Return true when a literal matcher can be below ROOT."
  (or (eq (darwin--matcher-kind matcher) :regex)
      (darwin--path-under-p (darwin--matcher-value matcher) root)))

(defun darwin--exclusion-forms (matcher)
  "Return require-not forms for one excluded matcher."
  (case (darwin--matcher-kind matcher)
    (:subpath
     (let ((path (darwin--sbpl-string (darwin--matcher-value matcher))))
       (list (format nil "(require-not (literal ~A))" path)
             (format nil "(require-not (subpath ~A))" path))))
    (:regex
     (list (format nil "(require-not (regex ~A))"
                   (darwin--regex-string (darwin--matcher-value matcher)))))))

(defun darwin--protected-metadata-regex (root name)
  "Return a regex matching ROOT/NAME and every descendant."
  (let* ((root (string-right-trim
                "/"
                (uiop:native-namestring (darwin--normalize-path root))))
         (prefix (if (string= root "") "/" (concatenate 'string root "/"))))
    (format nil "^~A~A(/.*)?$"
            (darwin--regex-escape prefix)
            (darwin--regex-escape name))))

(defun darwin--allow-policy (operation rules exclusions protected-regexes)
  "Build filtered allow forms for OPERATION.

A broad allow is never followed by a deny in this profile.  Every narrower
exception is instead a require-not filter on the broad allow, while a narrower
positive rule gets its own allow and can reopen a denied parent."
  (let ((components nil))
    (dolist (rule rules)
      (when (darwin--access-grants (darwin--resolved-rule-access rule)
                                   operation)
        (let ((matcher (darwin--resolved-rule-matcher rule))
              (parts nil))
          (case (darwin--matcher-kind matcher)
            (:subpath
             (push (format nil "(subpath ~A)"
                           (darwin--sbpl-string
                            (darwin--matcher-value matcher)))
                   parts)))
          (dolist (excluded-rule exclusions)
            (let ((exclusion
                    (darwin--resolved-rule-matcher excluded-rule)))
              (when (or (eq (darwin--matcher-kind exclusion) :regex)
                        (and (eq (darwin--matcher-kind matcher) :subpath)
                             (darwin--matcher-under-root-p
                              exclusion
                              (darwin--matcher-value matcher))))
                (setf parts
                      (append parts (darwin--exclusion-forms exclusion))))))
          (when (and (eq operation :write)
                     (eq (darwin--matcher-kind matcher) :subpath))
            (dolist (regex protected-regexes)
              (setf parts
                    (append parts
                            (list (format nil "(require-not (regex ~A))"
                                          (darwin--regex-string regex)))))))
          (push (if (cdr parts)
                    (format nil "(require-all ~{~A~^ ~})" (nreverse parts))
                    (first parts))
                components))))
    (when components
      (format nil "(allow ~A~%~{  ~A~^ ~}~%)"
              (if (eq operation :read) "file-read*" "file-write*")
              (nreverse components)))))

(defun darwin--profile (policy cwd)
  "Build an SBPL profile for POLICY, or reject an unrepresentable guarantee."
  (when (eq (sandbox-policy-network policy) :proxy-only)
    (error 'sandbox-unavailable :capability :network-proxy-only
           :message "macOS Seatbelt does not implement proxy-only networking."))
  (when (sandbox-policy-mount-proc-p policy)
    (error 'sandbox-unavailable :capability :mount-proc
           :message "macOS Seatbelt cannot provide a fresh procfs."))
  (when (sandbox-policy-isolate-processes-p policy)
    (error 'sandbox-unavailable :capability :process-namespaces
           :message "macOS Seatbelt cannot provide Linux user, PID, IPC, and UTS namespaces."))
  (let* ((rules (darwin--resolve-rules policy cwd))
         (implicit-rules
           (append
            (when (eq (sandbox-policy-filesystem-kind policy) :unrestricted)
              (list (darwin--make-resolved-rule
                     (darwin--subpath-matcher #P"/") :write)))
            (loop for root in +darwin-platform-read-roots+
                  when (probe-file root)
                    collect (darwin--make-resolved-rule
                             (darwin--subpath-matcher root) :read))))
         (all-rules (append implicit-rules rules))
         (protected-regexes
           (loop for root in (sandbox-policy-workspace-roots policy)
                 append (loop for name in
                                  (sandbox-policy-protected-metadata-names policy)
                              collect (darwin--protected-metadata-regex root name))))
         (read-policy
           (darwin--allow-policy :read all-rules
                                 (remove-if
                                  (lambda (rule)
                                    (darwin--access-grants
                                     (darwin--resolved-rule-access rule) :read))
                                  rules)
                                 nil))
         (write-policy
           (darwin--allow-policy :write all-rules
                                 (remove-if
                                  (lambda (rule)
                                    (darwin--access-grants
                                     (darwin--resolved-rule-access rule) :write))
                                  rules)
                                 protected-regexes))
         (forms (list "(version 1)"
                      "(deny default)"
                      "(allow process*)"
                      "(allow sysctl-read)"
                      "(allow mach-lookup)")))
    (when read-policy (setf forms (append forms (list read-policy))))
    (when write-policy (setf forms (append forms (list write-policy))))
    (when (eq (sandbox-policy-network policy) :enabled)
      (setf forms (append forms (list "(allow network*)"))))
    (format nil "~{~A~%~}" forms)))

(defun darwin--seatbelt-plan
    (program arguments policy cwd environment clear-environment-p)
  "Return a launch plan using the absolute system Seatbelt executable."
  (unless (darwin--seatbelt-executable)
    (error 'sandbox-unavailable :capability :seatbelt
           :message "The trusted /usr/bin/sandbox-exec executable is unavailable."))
  ;; Build the profile before creating its temporary file so unsupported policy
  ;; requests do not leave cleanup obligations behind.
  (let ((profile-text (darwin--profile policy cwd))
        (profile
          (merge-pathnames
           (format nil "cl-exec-sandbox-seatbelt-~36R.sb"
                   (random most-positive-fixnum))
           (uiop:temporary-directory))))
    (handler-case
        (progn
          (with-open-file (stream profile :direction :output :if-exists :error
                                  :if-does-not-exist :create)
            (write-string profile-text stream))
          (make-instance 'sandbox-plan
                         :program #P"/usr/bin/sandbox-exec"
                         :arguments (append
                                     (list "-f" (uiop:native-namestring profile) "--")
                                     (list (uiop:native-namestring program))
                                     arguments)
                         :environment environment
                         :environment-provided-p
                         (or environment clear-environment-p)
                         :working-directory cwd
                         :cleanup-paths (list profile)))
      (error (condition)
        (execute--safe-delete profile)
        (error 'sandbox-unavailable :capability :seatbelt
               :message (format nil "Could not construct a macOS Seatbelt profile: ~A"
                                 condition))))))
