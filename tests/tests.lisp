(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-posix))

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

(defun tests--darwin-p ()
  "Return true when the test process is running on Darwin."
  (member :darwin *features*))

(defun tests--write (path text)
  "Write TEXT to PATH and return PATH."
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-does-not-exist :create
                          :if-exists :supersede)
    (write-string text stream))
  path)

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
                 "the active backend reports filesystem enforcement")
    (when (tests--darwin-p)
      (test-assert (not (sandbox-supported-p :network-proxy-only))
                   "Darwin reports proxy-only networking as unsupported")
      (test-assert (eq (getf (sandbox-capabilities) :backend) :seatbelt)
                   "Darwin reports the Seatbelt backend")
      (test-assert
       (eq (not (null (getf (sandbox-capabilities) :available-p)))
           (not (null (cl-exec-sandbox::darwin--seatbelt-executable))))
       "Darwin capability discovery uses Seatbelt executable validation")))
  nil)

(defun test-darwin-profile-filters ()
  "Test Darwin uses filtered allows rather than overriding deny forms."
  (when (tests--darwin-p)
    (let* ((root (tests--temporary-root))
           (blocked (merge-pathnames "blocked/" root))
           (policy
             (make-sandbox-policy
              :workspace-roots (list root)
              :mount-proc-p nil
              :isolate-processes-p nil
              :filesystem-rules
              (list
               (make-filesystem-rule :kind :special :path :root :access :read)
               (make-filesystem-rule :kind :path :path root :access :write)
               (make-filesystem-rule :kind :path :path blocked :access :deny)))))
      (unwind-protect
           (let ((profile (cl-exec-sandbox::darwin--profile policy root)))
             (test-assert (search "(require-all" profile)
                          "Seatbelt composes filtered access requirements")
             (test-assert (search "(require-not (literal" profile)
                          "Seatbelt excludes the denied path itself")
             (test-assert (search "(require-not (subpath" profile)
                          "Seatbelt excludes the denied path subtree")
             (test-assert (search "(require-not (regex \"" profile)
                          "Seatbelt protects metadata with a regex")
             (test-assert (not (search "(deny file-write" profile))
                          "Seatbelt does not rely on later write denies")
             (test-assert (search "(allow process-exec)" profile)
                          "Seatbelt permits only executable child processes")
             (test-assert (search "(allow process-fork)" profile)
                          "Seatbelt permits child process creation")
             (test-assert (search "(allow signal (target same-sandbox))" profile)
                          "Seatbelt limits signals to same-sandbox processes")
             (test-assert (search "(allow process-info* (target same-sandbox))" profile)
                          "Seatbelt limits process information to same-sandbox processes")
             (test-assert (not (search "(allow process*)" profile))
                          "Seatbelt omits the broad process permission")
             (test-assert (not (search "(allow sysctl-read)" profile))
                          "Seatbelt omits unfiltered sysctl reads")
             (test-assert (not (search "(allow mach-lookup)" profile))
                          "Seatbelt omits unfiltered Mach service lookup")
             (test-assert (search "(sysctl-name \"hw.ncpu\")" profile)
                          "Seatbelt enumerates required sysctl names")
             (test-assert (search "com.apple.system.opendirectoryd.libinfo" profile)
                          "Seatbelt names the required directory-service lookup")
        (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))
  nil))

(defun test-darwin-default-policy-rejection ()
  "Test Darwin rejects a generic policy asking for Linux-only capabilities."
  (when (tests--darwin-p)
    (test-assert
     (handler-case
         (progn
           (sandbox-build-plan "/bin/true" nil
                               :policy (make-sandbox-policy))
           nil)
       (sandbox-unavailable (condition)
         (eq (sandbox-unavailable-capability condition) :mount-proc)))
     "Darwin rejects the generic Linux process-isolation defaults"))
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
         (readable (merge-pathnames "readable/" blocked))
         (secret (tests--write (merge-pathnames "secret.txt" blocked) "secret"))
         (readable-secret
           (tests--write (merge-pathnames "value.txt" readable) "visible"))
         (output (merge-pathnames "new.txt" allowed)))
    (ensure-directories-exist output)
    (let ((policy
            (make-sandbox-policy
             :workspace-roots (list root)
             :mount-proc-p (not (tests--darwin-p))
             :isolate-processes-p (not (tests--darwin-p))
             :filesystem-rules
             (list
              (make-filesystem-rule :kind :special :path :root :access :read)
              (make-filesystem-rule :kind :path :path root :access :write)
              (make-filesystem-rule :kind :path :path blocked :access :deny)
              (make-filesystem-rule :kind :path :path readable :access :read)
              (make-filesystem-rule :kind :path :path allowed :access :write)))))
      (unwind-protect
           (let ((result
                   (run-sandboxed
                    "/bin/sh"
                    (list "-c"
                          (format nil "cat ~A 2>/dev/null || true; cat ~A; printf ok > ~A"
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring secret))
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring readable-secret))
                                  (uiop:escape-shell-token
                                   (uiop:native-namestring output))))
                    :policy policy
                    :working-directory root)))
             (test-assert (not (search "secret" (sandbox-result-output result)))
                          "an exact deny masks readable content")
             (test-assert (search "visible" (sandbox-result-output result))
                          "a narrower read rule reopens a denied parent")
             (test-assert (string= (uiop:read-file-string output) "ok")
                          "a narrower write rule reopens a denied parent"))
        (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))
  nil)

(defun test-quoted-workspace-path ()
  "Test SBPL and shell quoting for workspace paths with spaces and quotes."
  (let* ((base (tests--temporary-root))
         (root (merge-pathnames "workspace with \"quotes\"/" base))
         (file (merge-pathnames "value with spaces.txt" root))
         (policy (workspace-write-sandbox-policy
                  :workspace-roots (list root)
                  :write-tmpdir-p nil
                  :write-slash-tmp-p nil)))
    (ensure-directories-exist file)
    (unwind-protect
         (let ((result
                 (run-sandboxed
                  "/bin/sh"
                  (list "-c"
                        (format nil "printf ok > ~A"
                                (uiop:escape-shell-token
                                 (uiop:native-namestring file))))
                  :policy policy
                  :working-directory root)))
           (test-assert (zerop (sandbox-result-exit-code result))
                        "quoted workspace paths launch successfully")
           (test-assert (string= (uiop:read-file-string file) "ok")
                        "quoted workspace paths remain writable"))
      (uiop:delete-directory-tree base :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-deny-glob ()
  "Test a deny glob masks matching files without masking other project files."
  (let* ((root (tests--temporary-root))
         (secret (tests--write (merge-pathnames "private.key" root) "secret"))
         (public (tests--write (merge-pathnames "public.txt" root) "public"))
         (pattern (if (tests--darwin-p)
                      (concatenate 'string (uiop:native-namestring root) "*.key")
                      "*.key"))
         (policy
           (make-sandbox-policy
            :workspace-roots (list root)
            :mount-proc-p (not (tests--darwin-p))
            :isolate-processes-p (not (tests--darwin-p))
            :filesystem-rules
            (list
             (make-filesystem-rule :kind :special :path :root :access :read)
             (make-filesystem-rule :kind :path :path root :access :write)
             (make-filesystem-rule :kind :glob :path pattern :access :deny)))))
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

(defun test-darwin-absolute-deny-glob-translation ()
  "Test absolute Darwin globs canonicalize only their static prefix."
  (when (tests--darwin-p)
    (let* ((root (tests--temporary-root))
           (pattern (concatenate 'string
                                 (uiop:native-namestring root)
                                 "*.key"))
           (regex (cl-exec-sandbox::darwin--glob-regex pattern root)))
      (unwind-protect
           (progn
             (test-assert (search (string-right-trim
                                   "/"
                                   (uiop:native-namestring (truename root)))
                                  regex)
                          "absolute Darwin globs retain their canonical prefix")
             (test-assert (search "[^/]*\\.key" regex)
                          "absolute Darwin globs retain wildcard syntax as regex text"))
        (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore))))
  nil)

(defun test-direct-full-access ()
  "Test unrestricted enabled networking keeps the direct launch path."
  (let* ((root (tests--temporary-root))
         (file (merge-pathnames "direct.txt" root))
         (policy (unrestricted-sandbox-policy))
         (plan (sandbox-build-plan "/bin/true" nil :policy policy))
         (result
           (run-sandboxed
            "/bin/sh"
            (list "-c"
                  (format nil "printf ok > ~A"
                          (uiop:escape-shell-token
                           (uiop:native-namestring file))))
            :policy policy
            :working-directory root)))
    (unwind-protect
         (progn
           (test-assert (string= (uiop:native-namestring
                                  (sandbox-plan-program plan))
                                 "/bin/true")
                        "full access uses the requested program directly")
           (test-assert (null (sandbox-plan-cleanup-paths plan))
                        "full access creates no transient sandbox files")
           (test-assert (zerop (sandbox-result-exit-code result))
                        "full access command succeeds")
           (test-assert (string= (uiop:read-file-string file) "ok")
                        "full access command can write anywhere"))
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-network-profile-modes ()
  "Test enabled networking is allowed and isolated networking is default-denied."
  (when (tests--darwin-p)
    (let ((enabled (cl-exec-sandbox::darwin--profile
                    (read-only-sandbox-policy :network :enabled)
                    (uiop:getcwd)))
          (isolated (cl-exec-sandbox::darwin--profile
                     (read-only-sandbox-policy :network :isolated)
                     (uiop:getcwd))))
      (test-assert (search "(allow network*)" enabled)
                   "Seatbelt allows enabled networking")
      (test-assert (not (search "(allow network*)" isolated))
                   "Seatbelt leaves isolated networking default-denied")))
  nil)

(defun test-enabled-network ()
  "Test enabled networking can reach a local listener under Seatbelt."
  (when (tests--darwin-p)
    (multiple-value-bind (server thread port)
        (tests--start-proxy-server)
      (unwind-protect
           (let ((result
                   (run-sandboxed
                    "/bin/bash"
                    '("-c"
                      "exec 3<>/dev/tcp/127.0.0.1/$PORT; IFS= read -r -n 4 reply <&3; printf %s \"$reply\"")
                    :policy (read-only-sandbox-policy :network :enabled)
                    :environment (list (format nil "PORT=~D" port))
                    :timeout 3)))
             (test-assert (zerop (sandbox-result-exit-code result))
                          "enabled networking reaches a local listener")
             (test-assert (string= (sandbox-result-output result) "pong")
                          "enabled networking carries local socket data"))
        (sb-bsd-sockets:socket-close server)
        (sb-thread:join-thread thread :default nil))))
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
                            (uiop:native-namestring (truename root)))))
          "direct execution applies working directory and environment")
      (uiop:delete-directory-tree root :validate t :if-does-not-exist :ignore)))
  nil)

(defun test-sandbox-environment-and-cleanup ()
  "Test sandbox environment replacement and private Seatbelt profile cleanup."
  (when (tests--darwin-p)
    (labels ((profile-names ()
               (sort
                (mapcar #'uiop:native-namestring
                        (directory
                         (merge-pathnames
                          ".cl-exec-sandbox-seatbelt-*/*.sb"
                          (user-homedir-pathname))))
                #'string<)))
      (let ((before (profile-names)))
        (let ((plan
                (sandbox-build-plan "/bin/true" nil
                                    :policy (read-only-sandbox-policy))))
          (unwind-protect
               (let* ((paths (sandbox-plan-cleanup-paths plan))
                      (profile (find-if
                                (lambda (path)
                                  (search ".sb"
                                          (uiop:native-namestring path)))
                                paths))
                      (directory (uiop:pathname-directory-pathname profile)))
                 (test-assert profile
                              "Seatbelt plans retain the transient profile path")
                 (test-assert
                  (not (cl-exec-sandbox::linux--path-under-p
                        profile (uiop:temporary-directory)))
                  "Seatbelt profiles stay outside the default temporary root")
                 (test-assert
                  (= (logand (sb-posix:stat-mode (sb-posix:stat directory)) #o777)
                     #o700)
                  "Seatbelt profile directories are private")
                 (dolist (path (reverse paths))
                   (cl-exec-sandbox::execute--safe-delete path))
                 (test-assert (every (lambda (path) (not (probe-file path)))
                                     paths)
                              "Seatbelt cleanup removes the profile and private directory"))
            (dolist (path (reverse (sandbox-plan-cleanup-paths plan)))
              (cl-exec-sandbox::execute--safe-delete path))))
        (let ((result
                (run-sandboxed
                 "/bin/sh"
                 '("-c" "printf %s \"$VALUE\"")
                 :policy (read-only-sandbox-policy)
                 :environment '("VALUE=present")
                 :clear-environment-p t)))
          (test-assert (string= (sandbox-result-output result) "present")
                       "sandbox execution receives its explicit environment")
          (test-assert (equal before (profile-names))
                       "Seatbelt profile files and directories are removed after execution")))))
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

(defun test-isolated-network-seccomp ()
  "Test restricted networking denies Internet socket creation."
  (let ((result
          (run-sandboxed
           "/bin/bash"
           '("-c" "exec 3<>/dev/tcp/127.0.0.1/1")
           :policy (read-only-sandbox-policy))))
    (test-assert (not (zerop (sandbox-result-exit-code result)))
                 "isolated networking rejects an Internet socket")
    (when (not (tests--darwin-p))
      (test-assert (search "Operation not permitted"
                           (sandbox-result-error-output result)
                           :test #'char-equal)
                   "isolated networking reports a seccomp denial")))
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

(defun test-proxy-only-network ()
  "Test proxy-only networking or its explicit Darwin rejection."
  (if (tests--darwin-p)
      (test-assert
       (handler-case
           (progn
             (sandbox-build-plan "/bin/sh" '("-c" "true")
                                 :policy (read-only-sandbox-policy
                                          :network :proxy-only))
             nil)
         (sandbox-unavailable (condition)
           (eq (sandbox-unavailable-capability condition)
               :network-proxy-only)))
       "Darwin reports proxy-only networking as unsupported")
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
          (sb-thread:join-thread thread :default nil))))
  nil)

(defun run-tests ()
  "Run all cl-exec-sandbox tests and return true."
  (setf *test-count* 0)
  (test-policy-validation)
  (test-darwin-profile-filters)
  (test-darwin-default-policy-rejection)
  (test-bwrap-override)
  (test-read-only-enforcement)
  (test-workspace-write-enforcement)
  (test-missing-protected-metadata)
  (test-deny-and-nested-override)
  (test-quoted-workspace-path)
  (test-deny-glob)
  (test-darwin-absolute-deny-glob-translation)
  (test-direct-full-access)
  (test-network-profile-modes)
  (test-enabled-network)
  (test-unrestricted-filesystem-with-isolated-network)
  (test-external-execution-context)
  (test-sandbox-environment-and-cleanup)
  (test-timeout)
  (test-merged-output)
  (test-isolated-network-seccomp)
  (test-proxy-only-network)
  (format t "~&~D cl-exec-sandbox tests passed.~%" *test-count*)
  t)
