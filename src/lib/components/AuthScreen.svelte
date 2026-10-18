<script lang="ts">
  import { estimatePasswordStrength } from '../password-generator';
  import {
    acknowledgeRegistration,
    app,
    isSecureContextOk,
    openRecoverFlow,
    setAuthMode,
    setUpRecoveryAfterRegistration,
    submitAuth,
    usernameProblem,
  } from '../store.svelte';
  import { checkNewPassword } from '../vaultcrypto';
  import NativeField from './NativeField.svelte';
  import RecoverAccountDialog from './RecoverAccountDialog.svelte';

  let username = $state('');
  let password = $state('');
  let confirmPassword = $state('');
  let inviteCode = $state('');
  let busy = $derived(app.pending.auth);
  const registering = $derived(app.authMode === 'register');

  const strengthLabel = { weak: 'Weak', fair: 'Fair', strong: 'Strong', excellent: 'Excellent' } as const;
  const strength = $derived(estimatePasswordStrength(password));

  // Live hints while creating an account (only once the user typed something).
  const usernameHint = $derived(registering && username ? usernameProblem(username) : null);
  const passwordHint = $derived(registering && password ? checkNewPassword(password) : null);
  const confirmHint = $derived(
    registering && confirmPassword && confirmPassword !== password ? 'The passwords do not match.' : null,
  );

  const onTabsChange = (event: Event): void => {
    const target = event.target as HTMLElement & { activeTabIndex: number };
    setAuthMode(target.activeTabIndex === 1 ? 'register' : 'login');
    confirmPassword = '';
  };

  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    void submitAuth({ username, password, confirmPassword, inviteCode });
  };
</script>

<div class="auth-shell">
  <div class="auth-panel">
    <div class="brand-lockup" style="justify-content: center">
      <div class="brand-mark" aria-hidden="true">xV</div>
      <div>
        <p class="eyebrow">xVault</p>
        <h1>Encrypted 2FA vault</h1>
      </div>
    </div>

    {#if app.registerLoginId}
      <div class="notice notice--success" role="status">
        <p style="margin: 0 0 6px; font-weight: 500">Welcome, {app.registerLoginId}!</p>
        <p style="margin: 0">
          Your vault is ready. Sign in from any device with your username
          <strong class="mono">{app.registerLoginId}</strong> and your password.
        </p>
      </div>

      <div class="notice notice--info" role="note">
        <p style="margin: 0 0 6px; font-weight: 500">One last step: a recovery phrase</p>
        <p style="margin: 0">
          Your password never leaves this browser, so nobody — not even the
          server — can reset it. A recovery phrase (24 words to write down) is
          the only way back in if you ever forget it.
        </p>
      </div>

      <md-filled-button style="width: 100%" onclick={() => void setUpRecoveryAfterRegistration()}>
        <md-icon slot="icon">key</md-icon>
        Create my recovery phrase
      </md-filled-button>
      <md-text-button style="width: 100%" onclick={acknowledgeRegistration}>
        Later — open my vault
      </md-text-button>
    {:else}
      <div class="auth-panel__heading">
        <p class="eyebrow">{registering ? 'New account' : 'Welcome back'}</p>
        <h2>
          {registering ? 'Create your encrypted vault.' : 'Sign in to your vault.'}
        </h2>
      </div>

      <md-tabs activeTabIndex={registering ? 1 : 0} onchange={onTabsChange}>
        <md-primary-tab>Sign in</md-primary-tab>
        {#if app.registrationEnabled}
          <md-primary-tab>Create account</md-primary-tab>
        {/if}
      </md-tabs>

      {#if !isSecureContextOk()}
        <div class="notice" role="alert">
          This page is not served over HTTPS. xVault encrypts everything in
          your browser and refuses to run on an insecure connection.
        </div>
      {/if}

      {#if !app.registrationEnabled}
        <p class="supporting-text" role="note">
          New accounts are disabled on this server.
        </p>
      {/if}

      <form class="stack-md" novalidate onsubmit={submit}>
        <div class="stack-xs">
          <NativeField
            label="Username"
            type="text"
            name="username"
            id="auth-username"
            autocomplete="username"
            placeholder={registering ? 'e.g. matthew' : 'Your username'}
            bind:value={username}
          />
          {#if registering}
            <p class="field-hint" class:field-hint--error={!!usernameHint}>
              {usernameHint ?? '3–32 characters: letters, digits, . _ - · not case-sensitive'}
            </p>
          {/if}
        </div>

        <div class="stack-xs">
          <NativeField
            label="Password"
            type="password"
            name="password"
            id="auth-password"
            autocomplete={registering ? 'new-password' : 'current-password'}
            placeholder={registering ? 'At least 12 characters' : 'Your password'}
            bind:value={password}
          />
          {#if registering && password}
            <div class="strength" aria-live="polite">
              <div class="strength__bar">
                <span class="strength__fill strength__fill--{strength}"></span>
              </div>
              <span class="strength__label">{strengthLabel[strength]}</span>
            </div>
            {#if passwordHint}
              <p class="field-hint field-hint--error">{passwordHint}</p>
            {/if}
          {/if}
        </div>

        {#if registering}
          <div class="stack-xs">
            <NativeField
              label="Confirm password"
              type="password"
              name="confirm-password"
              id="auth-password-confirm"
              autocomplete="new-password"
              placeholder="Type it again"
              bind:value={confirmPassword}
            />
            {#if confirmHint}
              <p class="field-hint field-hint--error">{confirmHint}</p>
            {/if}
          </div>

          {#if app.inviteRequired}
            <NativeField
              label="Invitation code"
              type="password"
              name="inviteCode"
              id="auth-invite-code"
              autocomplete="off"
              placeholder="Provided by the server administrator"
              bind:value={inviteCode}
            />
          {/if}
        {/if}

        {#if app.authError}
          <div class="notice" role="alert">{app.authError}</div>
        {/if}

        {#if registering}
          <p class="supporting-text">
            Everything is encrypted in this browser with a key derived from your
            password (Argon2id + AES-256-GCM). The server only stores ciphertext
            and can never read or reset it — pick a passphrase you will remember.
          </p>
        {/if}

        <md-filled-button style="width: 100%" type="submit" disabled={busy}>
          {#if busy}
            {registering ? 'Creating your vault…' : 'Unlocking…'}
          {:else if registering}
            Create account
          {:else}
            Sign in
          {/if}
        </md-filled-button>

        {#if !registering}
          <div class="inline-actions" style="justify-content: center">
            <md-text-button type="button" onclick={() => openRecoverFlow()}>
              Forgot password?
            </md-text-button>
          </div>
        {/if}
      </form>
    {/if}
  </div>
</div>

<RecoverAccountDialog initialLoginId={username} />

<style>
  .stack-xs {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .field-hint {
    margin: 0;
    font-size: 12px;
    color: var(--md-sys-color-on-surface-variant);
  }

  .field-hint--error {
    color: var(--md-sys-color-error);
  }

  .strength {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .strength__bar {
    flex: 1;
    height: 4px;
    border-radius: 2px;
    background: var(--md-sys-color-surface-container-highest);
    overflow: hidden;
  }

  .strength__fill {
    display: block;
    height: 100%;
    border-radius: 2px;
    transition: width 0.2s ease;
  }

  .strength__fill--weak {
    width: 25%;
    background: var(--md-sys-color-error);
  }

  .strength__fill--fair {
    width: 50%;
    background: #e0a33a;
  }

  .strength__fill--strong {
    width: 75%;
    background: var(--md-sys-color-primary);
  }

  .strength__fill--excellent {
    width: 100%;
    background: var(--md-sys-color-primary);
  }

  .strength__label {
    font-size: 12px;
    min-width: 64px;
    text-align: right;
    color: var(--md-sys-color-on-surface-variant);
  }
</style>
