(in-package #:cl-exec-sandbox)

;;;; -- macOS Seatbelt backend --

(defparameter +darwin-platform-read-roots+
  '(#P"/bin/" #P"/sbin/" #P"/usr/" #P"/System/" #P"/Library/" #P"/private/" )
  "System directories needed by ordinary macOS command interpreters.")

(defun darwin--sbpl-string (value)
  "Quote VALUE for an SBPL string literal, canonicalizing existing paths."
  (let ((path (if (probe-file value) (truename value) (pathname value))))
    (with-output-to-string (stream)
      (write-char #\" stream)
      (loop for character across (uiop:native-namestring path) do
      (when (member character '(#\\ #\")) (write-char #\\ stream))
      (write-char character stream))
      (write-char #\" stream))))

(defun darwin--rule (operation path)
  "Return an SBPL path operation for PATH."
  (format nil "(allow ~A (subpath ~A))" operation
          (darwin--sbpl-string path)))

(defun darwin--glob-regex (pattern)
  "Translate the small, documented glob language into an SBPL regex."
  (with-output-to-string (stream)
    (write-string "^" stream)
    (loop for character across pattern do
      (case character
        (#\* (write-string ".*" stream))
        (#\? (write-char #\. stream))
        (otherwise
         (when (find character "\\.+()[]{}^$|") (write-char #\\ stream))
         (write-char character stream))))
    (write-string "$" stream)))

(defun darwin--glob-rule (operation pattern root)
  "Return an SBPL regex rule for PATTERN below ROOT."
  (format nil "(allow ~A (regex ~A))" operation
          (darwin--sbpl-string
           (concatenate 'string "^" (uiop:native-namestring root)
                        (darwin--glob-regex pattern)))))

(defun darwin--profile (policy cwd)
  "Build an SBPL profile for POLICY, or reject an unrepresentable guarantee."
  (when (sandbox-policy-mount-proc-p policy)
    (error 'sandbox-unavailable :capability :mount-proc
           :message "macOS Seatbelt cannot provide a fresh procfs."))
  (when (sandbox-policy-isolate-processes-p policy)
    (error 'sandbox-unavailable :capability :process-namespaces
           :message "macOS Seatbelt cannot provide Linux user, PID, IPC, and UTS namespaces."))
  (let ((forms nil))
    (dolist (form '("(allow mach-lookup)"
                    "(allow sysctl-read)"
                    "(allow process*)"
                    "(deny default)"
                    "(version 1)"))
      (push form forms))
    (labels ((add (form) (setf forms (append forms (list form))))
             (path-rule (access path)
               (case access
                 (:read (add (darwin--rule "file-read*" path)))
                 (:write (progn (add (darwin--rule "file-read*" path))
                                (add (darwin--rule "file-write*" path))))
                 (:deny (add (format nil "(deny file-read* file-write* (subpath ~A))"
                                      (darwin--sbpl-string path)))))))
      (when (eq (sandbox-policy-filesystem-kind policy) :unrestricted)
        (add "(allow file-read* file-write*)"))
      (dolist (root +darwin-platform-read-roots+)
        (when (probe-file root) (path-rule :read root)))
      (dolist (rule (sandbox-policy-filesystem-rules policy))
        (case (filesystem-rule-kind rule)
          (:path (path-rule (filesystem-rule-access rule)
                            (linux--absolute-path (filesystem-rule-path rule) cwd)))
          (:special
           (dolist (path (linux--special-paths rule policy cwd))
             (let ((access (filesystem-rule-access rule)))
               (path-rule :read path)
               (when (eq access :write)
                 (add (darwin--rule "file-write*" path)))
               (when (eq access :deny)
                 (add (format nil "(deny file-read* file-write* (subpath ~A))"
                              (darwin--sbpl-string path)))))))
          (:glob
           (dolist (root (or (sandbox-policy-workspace-roots policy) (list cwd)))
             (add (darwin--glob-rule "file-read*"
                                      (filesystem-rule-path rule) root))
             (add (format nil "(deny file-read* file-write* (regex ~A))"
                          (darwin--sbpl-string
                           (concatenate 'string "^" (uiop:native-namestring root)
                                        (darwin--glob-regex (filesystem-rule-path rule)))))))))
      (dolist (root (sandbox-policy-workspace-roots policy))
        (dolist (name (sandbox-policy-protected-metadata-names policy))
          (dolist (operation '("file-write-create" "file-write-data"
                               "file-write-unlink" "file-write-mode"
                               "file-write-owner" "file-write-flags"))
            (add (format nil "(deny ~A (subpath ~A))" operation
                         (darwin--sbpl-string
                          (merge-pathnames (format nil "~A/" name) root))))))
        (when (find-if (lambda (rule)
                         (and (eq (filesystem-rule-kind rule) :special)
                              (eq (filesystem-rule-path rule) :workspace-roots)
                              (eq (filesystem-rule-access rule) :write)))
                       (sandbox-policy-filesystem-rules policy))
          (add (darwin--rule "file-read*" root))
          (dolist (operation '("file-write-create" "file-write-data"
                               "file-write-unlink" "file-write-mode"
                               "file-write-owner" "file-write-flags"))
            (add (darwin--rule operation root))))
        (dolist (name (sandbox-policy-protected-metadata-names policy))
          (add (format nil "(deny file-write* (subpath ~A))"
                       (darwin--sbpl-string (merge-pathnames (format nil "~A/" name) root))))))
      (unless (eq (sandbox-policy-network policy) :enabled)
        ;; The default deny already blocks network-client and network-outbound.
        (add "(deny network*)"))
      (return-from darwin--profile
        (format nil "~{~A~%~}" forms))))))

(defun darwin--seatbelt-plan (program arguments policy cwd environment clear-environment-p)
  "Return a launch plan using the absolute system Seatbelt executable."
  (let ((profile (merge-pathnames
                  (format nil "cl-exec-sandbox-seatbelt-~36R.sb" (random most-positive-fixnum))
                  (uiop:temporary-directory))))
    (handler-case
        (progn
          (with-open-file (stream profile :direction :output :if-exists :error
                                  :if-does-not-exist :create)
            (write-string (darwin--profile policy cwd) stream))
          (make-instance 'sandbox-plan
                         :program #P"/usr/bin/sandbox-exec"
                         :arguments (append (list "-f" (uiop:native-namestring profile) "--")
                                             (list (uiop:native-namestring program)) arguments)
                         :environment environment
                         :environment-provided-p (or environment clear-environment-p)
                         :working-directory cwd
                         :cleanup-paths (list profile)))
      (error (condition)
        (execute--safe-delete profile)
        (error 'sandbox-unavailable :capability :seatbelt
               :message (format nil "Could not construct a macOS Seatbelt profile: ~A" condition))))))
