<script lang="ts">
  import {
    app,
    closeRecoverFlow,
    recoverWithMasterKeyFile,
    recoverWithPhrase,
  } from '../store.svelte';

  let { initialLoginId = '' }: { initialLoginId?: string } = $props();

  let loginId = $state('');
  let method = $state<'phrase' | 'key'>('phrase');
  let phrase = $state('');
  let fileText = $state('');
  let fileName = $state('');
  let filePassphrase = $state('');
  let needsFilePassphrase = $state(false);
  let newPassword = $state('');
  let confirmPassword = $state('');
  let error = $state<string | null>(null);
  let attemptsLeft = $state<number | undefined>(undefined);

  $effect(() => {
    if (app.recoverFlowOpen) {
      loginId = initialLoginId;
      phrase = '';
      fileText = '';
      fileName = '';
      filePassphrase = '';
      needsFilePassphrase = false;
      newPassword = '';
      confirmPassword = '';
      error = null;
      attemptsLeft = undefined;
    }
  });

  const onFileChange = async (event: Event): Promise<void> => {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    fileName = file.name;
    fileText = await file.text();
    needsFilePassphrase = false;
  };

  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    error = null;
    attemptsLeft = undefined;

    if (method === 'phrase' && !loginId.trim()) {
      error = 'Username is required.';
      return;
    }
    if (newPassword.length < 12) {
      error = 'Use at least 12 characters for the new password.';
      return;
    }
    if (newPassword !== confirmPassword) {
      error = 'The new passwords do not match.';
      return;
    }

    if (method === 'phrase') {
      const result = await recoverWithPhrase(loginId.trim(), phrase, newPassword);
      if (!result.success) {
        error = result.error ?? 'Unable to recover this account.';
        attemptsLeft = result.attemptsLeft;
      }
      return;
    }

    if (!fileText) {
      error = 'Choose your .key recovery file.';
      return;
    }
    const result = await recoverWithMasterKeyFile(fileText, filePassphrase, newPassword);
    if (!result.success) {
      if (result.needsPassphrase) {
        needsFilePassphrase = true;
        error = 'This recovery file needs its passphrase.';
      } else {
        error = result.error ?? 'Unable to recover this account.';
        attemptsLeft = result.attemptsLeft;
      }
    }
  };
</script>

{#if app.recoverFlowOpen}
  <md-dialog
    open
    onclose={closeRecoverFlow}
    style="--md-dialog-container-color: var(--md-sys-color-surface-container-high)"
  >
    <div slot="headline">Restore access</div>
    <form slot="content" class="dialog-body" onsubmit={submit}>
      <md-outlined-text-field
        label="Username"
        value={loginId}
        oninput={(event: Event) => (loginId = (event.target as HTMLInputElement).value)}
        style="width: 100%"
        supporting-text="Not needed with a .key file — it already contains it."
      ></md-outlined-text-field>

      <div class="field-grid">
        <label class="radio-row">
          <input
            type="radio"
            name="recovery-method"
            value="phrase"
            checked={method === 'phrase'}
            onchange={() => (method = 'phrase')}
          />
          Recovery phrase
        </label>
        <label class="radio-row">
          <input
            type="radio"
            name="recovery-method"
            value="key"
            checked={method === 'key'}
            onchange={() => (method = 'key')}
          />
          Recovery key file
        </label>
      </div>

      {#if method === 'phrase'}
        <md-outlined-text-field
          label="24-word recovery phrase"
          type="textarea"
          rows="3"
          value={phrase}
          oninput={(event: Event) => (phrase = (event.target as HTMLInputElement).value)}
          style="width: 100%"
          supporting-text="Words separated by spaces, in order."
        ></md-outlined-text-field>
      {:else}
        <md-outlined-button type="button" onclick={() => document.getElementById('recover-key-file')?.click()}>
          <md-icon slot="icon">upload_file</md-icon>
          {fileName || 'Choose .key file'}
        </md-outlined-button>
        <input
          hidden
          id="recover-key-file"
          type="file"
          accept=".key,application/json"
          onchange={onFileChange}
        />
        {#if needsFilePassphrase}
          <md-outlined-text-field
            label="File passphrase"
            type="password"
            value={filePassphrase}
            oninput={(event: Event) => (filePassphrase = (event.target as HTMLInputElement).value)}
            style="width: 100%"
          ></md-outlined-text-field>
        {/if}
      {/if}

      <div class="field-grid">
        <md-outlined-text-field
          label="New password"
          type="password"
          autocomplete="new-password"
          value={newPassword}
          oninput={(event: Event) => (newPassword = (event.target as HTMLInputElement).value)}
          style="width: 100%"
        ></md-outlined-text-field>
        <md-outlined-text-field
          label="Confirm new password"
          type="password"
          autocomplete="new-password"
          value={confirmPassword}
          oninput={(event: Event) => (confirmPassword = (event.target as HTMLInputElement).value)}
          style="width: 100%"
        ></md-outlined-text-field>
      </div>

      {#if error}
        <div class="notice" role="alert">
          {error}
          {#if attemptsLeft !== undefined}
            <p style="margin: 6px 0 0">Attempts left: {attemptsLeft}</p>
          {/if}
        </div>
      {/if}

      <div class="dialog-actions">
        <md-text-button type="button" onclick={closeRecoverFlow}>Cancel</md-text-button>
        <md-filled-button type="submit" disabled={app.pending.recoverAccount}>
          {app.pending.recoverAccount ? 'Restoring...' : 'Reset password'}
        </md-filled-button>
      </div>
    </form>
  </md-dialog>
{/if}

<style>
  .radio-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
  }
</style>
