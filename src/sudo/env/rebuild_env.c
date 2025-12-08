// https://github.com/sudo-project/sudo/blob/8e0b9a9d475a46d35b78bc6718d44a56a278553e/plugins/sudoers/env.c#L859-L1137

#include <stdbool.h>
#include <stddef.h>

/*
 * Build a new environment and either clear potentially dangerous
 * variables from the old one or start with a clean slate.
 * Also adds sudo-specific variables (SUDO_*).
 * Returns true on success or false on failure.
 */
bool rebuild_env(const struct sudoers_context *ctx) {
  char **ep, *cp, *ps1;
  char idbuf[STRLEN_MAX_UNSIGNED(uid_t) + 1];
  unsigned int didvar;
  bool reset_home = false;
  int len;
  debug_decl(rebuild_env, SUDOERS_DEBUG_ENV);

  /*
   * Either clean out the environment or reset to a safe default.
   */
  ps1 = NULL;
  didvar = 0;
  env.env_len = 0;
  env.env_size = 128;
  sudoers_gc_remove(GC_PTR, env.old_envp);
  free(env.old_envp);
  env.old_envp = env.envp;
  env.envp = reallocarray(NULL, env.env_size, sizeof(char *));
  if (env.envp == NULL) {
    sudo_debug_printf(SUDO_DEBUG_ERROR | SUDO_DEBUG_LINENO,
                      "unable to allocate memory");
    env.env_size = 0;
    goto bad;
  }
  sudoers_gc_add(GC_PTR, env.envp);
  env.envp[0] = NULL;

  /* Reset HOME based on target user if configured to. */
  if (ISSET(ctx->mode, MODE_RUN)) {
    if (def_always_set_home ||
        ISSET(ctx->mode, MODE_RESET_HOME | MODE_LOGIN_SHELL) ||
        (ISSET(ctx->mode, MODE_SHELL) && def_set_home))
      reset_home = true;
  }

  if (def_env_reset || ISSET(ctx->mode, MODE_LOGIN_SHELL)) {
    /*
     * If starting with a fresh environment, initialize it based on
     * /etc/environment or login.conf.  For "sudo -i" we want those
     * variables to override the invoking user's environment, so we
     * defer reading them until later.
     */
    if (!ISSET(ctx->mode, MODE_LOGIN_SHELL)) {
      for (ep = env.envp; *ep; ep++)
        env_update_didvar(*ep, &didvar);
    }

    /* Pull in vars we want to keep from the old environment. */
    if (env.old_envp != NULL) {
      for (ep = env.old_envp; *ep; ep++) {
        bool keepit;

        /*
         * Look up the variable in the env_check and env_keep lists.
         */
        keepit = env_should_keep(ctx, *ep);

        /*
         * Do SUDO_PS1 -> PS1 conversion.
         * This must happen *after* env_should_keep() is called.
         */
        if (strncmp(*ep, "SUDO_PS1=", 9) == 0)
          ps1 = *ep + 5;

        if (keepit) {
          /* Preserve variable. */
          CHECK_PUTENV(*ep, true, false);
          env_update_didvar(*ep, &didvar);
        }
      }
    }
    didvar |= didvar << 16; /* convert DID_* to KEPT_* */

    /*
     * Add in defaults.  In -i mode these come from the runas user,
     * otherwise they may be from the user's environment (depends
     * on sudoers options).
     */
    if (ISSET(ctx->mode, MODE_LOGIN_SHELL)) {
      CHECK_SETENV2("SHELL", ctx->runas.pw->pw_shell, ISSET(didvar, DID_SHELL),
                    true);
      SET(didvar, DID_SHELL);
      CHECK_SETENV2("LOGNAME", ctx->runas.pw->pw_name,
                    ISSET(didvar, DID_LOGNAME), true);
      CHECK_SETENV2("USER", ctx->runas.pw->pw_name, ISSET(didvar, DID_USER),
                    true);
    } else {
      /* We will set LOGNAME later in the def_set_logname case. */
      if (!def_set_logname) {
        if (!ISSET(didvar, DID_LOGNAME))
          CHECK_SETENV2("LOGNAME", ctx->user.name, false, true);
        if (!ISSET(didvar, DID_USER))
          CHECK_SETENV2("USER", ctx->user.name, false, true);
      }
    }

    /* If we didn't keep HOME, reset it based on target user. */
    if (!ISSET(didvar, KEPT_HOME))
      reset_home = true;
  } else {
    /*
     * Copy environ entries as long as they don't match env_delete or
     * env_check.
     */
    if (env.old_envp != NULL) {
      for (ep = env.old_envp; *ep; ep++) {
        /* Add variable unless it matches a blocklist. */
        if (!env_should_delete(*ep)) {
          if (strncmp(*ep, "SUDO_PS1=", 9) == 0)
            ps1 = *ep + 5;
          else if (strncmp(*ep, "SHELL=", 6) == 0)
            SET(didvar, DID_SHELL);
          else if (strncmp(*ep, "PATH=", 5) == 0)
            SET(didvar, DID_PATH);
          else if (strncmp(*ep, "TERM=", 5) == 0)
            SET(didvar, DID_TERM);
          CHECK_PUTENV(*ep, true, false);
        }
      }
    }
  }
  /* Replace the PATH envariable with a secure one? */
  if (def_secure_path && !user_is_exempt(ctx)) {
    CHECK_SETENV2("PATH", def_secure_path, true, true);
    SET(didvar, DID_PATH);
  }

  /*
   * Set LOGIN, LOGNAME, and USER to target if "set_logname" is not
   * disabled.  We skip this if we are running a login shell (because
   * they have already been set).
   */
  if (def_set_logname && !ISSET(ctx->mode, MODE_LOGIN_SHELL)) {
    if ((didvar & KEPT_USER_VARIABLES) == 0) {
      /* Nothing preserved, set them all. */
      CHECK_SETENV2("LOGNAME", ctx->runas.pw->pw_name, true, true);
      CHECK_SETENV2("USER", ctx->runas.pw->pw_name, true, true);
    } else if ((didvar & KEPT_USER_VARIABLES) != KEPT_USER_VARIABLES) {
      /*
       * Preserved some of LOGIN, LOGNAME, USER but not all.
       * Make the unset ones match so we don't end up with some
       * set to the invoking user and others set to the runas user.
       */
      if (ISSET(didvar, KEPT_LOGNAME))
        cp = sudo_getenv("LOGNAME");
      else if (ISSET(didvar, KEPT_USER))
        cp = sudo_getenv("USER");
      else
        cp = NULL;
      if (cp != NULL) {
        if (!ISSET(didvar, KEPT_LOGNAME))
          CHECK_SETENV2("LOGNAME", cp, true, true);
        if (!ISSET(didvar, KEPT_USER))
          CHECK_SETENV2("USER", cp, true, true);
      }
    }
  }

  /* Set $HOME to target user if not preserving user's value. */
  if (reset_home)
    CHECK_SETENV2("HOME", ctx->runas.pw->pw_dir, true, true);

  /* Provide default values for $SHELL, $TERM and $PATH if not set. */
  if (!ISSET(didvar, DID_SHELL))
    CHECK_SETENV2("SHELL", ctx->runas.pw->pw_shell, false, false);
  if (!ISSET(didvar, DID_TERM))
    CHECK_PUTENV("TERM=unknown", false, false);
  if (!ISSET(didvar, DID_PATH))
    CHECK_SETENV2("PATH", _PATH_STDPATH, false, true);

  /* Set PS1 if SUDO_PS1 is set. */
  if (ps1 != NULL)
    CHECK_PUTENV(ps1, true, true);

  /* Add the SUDO_COMMAND envariable (cmnd + args). */
  if (ctx->user.cmnd_args) {
    /*
     * We limit ctx->user.cmnd_args to 4096 bytes to avoid an execve(2)
     * failure for very long argument vectors.  The command's environment
     * also counts against the ARG_MAX limit.
     */
    len = asprintf(&cp, "SUDO_COMMAND=%s %.*s", ctx->user.cmnd, 4096,
                   ctx->user.cmnd_args);
    if (len == -1)
      goto bad;
    if (sudo_putenv(cp, true, true) == -1) {
      free(cp);
      goto bad;
    }
    sudoers_gc_add(GC_PTR, cp);
  } else {
    CHECK_SETENV2("SUDO_COMMAND", ctx->user.cmnd, true, true);
  }

  /* Add the SUDO_{USER,UID,GID,HOME,TTY} environment variables. */
  CHECK_SETENV2("SUDO_USER", ctx->user.name, true, true);
  (void)snprintf(idbuf, sizeof(idbuf), "%u", (unsigned int)ctx->user.uid);
  CHECK_SETENV2("SUDO_UID", idbuf, true, true);
  (void)snprintf(idbuf, sizeof(idbuf), "%u", (unsigned int)ctx->user.gid);
  CHECK_SETENV2("SUDO_GID", idbuf, true, true);
  CHECK_SETENV2("SUDO_HOME", ctx->user.pw->pw_dir, true, true);
  if (ctx->user.ttypath != NULL)
    CHECK_SETENV2("SUDO_TTY", ctx->user.ttypath, true, true);

  debug_return_bool(true);

bad:
  sudo_warn("%s", U_("unable to rebuild the environment"));
  debug_return_bool(false);
}
