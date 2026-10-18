<script lang="ts">
  import {
    app,
    closeMasterKeyDialog,
    generateAndDownloadMasterKey,
  } from '../store.svelte';

  let password = $state('');
  let filePassphrase = $state('');
  let confirmPassphrase = $state('');

  $effect(() => {
    if (!app.masterKeyDialogOpen) {
      password = '';
      filePassphrase = '';
      confirmPassphrase = '';
    }
  });

  const passphraseMismatch = $derived(
    filePassphrase.length > 0 && filePassphrase !== confirmPassphrase,
  );

  const canSubmit = $derived(
    password.length > 0 &&
      filePassphrase.length >= 12 &&
      filePassphrase === confirmPassphrase,
  );

  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    if (!canSubmit) return;
    void generateAndDownloadMasterKey(password, filePassphrase);
  };
</script>

{#if app.masterKeyDialogOpen}
  <md-dialog
    open
    onclose={closeMasterKeyDialog}
    style="--md-dialog-container-color: var(--md-sys-color-surface-container-high)"
  >
    <div slot="headline">Generate recovery key file</div>
    <form slot="content" class="dialog-body" onsubmit={submit}>
      <p class="supporting-text">
        Downloads a <code class="mono">.key</code> file that can restore full
        access to this vault if you lose both your password and your
        recovery phrase. Store it offline, away from this device.
      </p>

      <md-outlined-text-field
        label="Current password"
        type="password"
        autocomplete="current-password"
        value={password}
        oninput={(event: Event) => (password = (event.target as HTMLInputElement).value)}
        style="width: 100%"
      ></md-outlined-text-field>


        <md-outlined-text-field
          label="File passphrase"
          type="password"
          value={filePassphrase}
          oninput={(event: Event) => (filePassphrase = (event.target as HTMLInputElement).value)}
          style="width: 100%"
          supporting-text="At least 12 characters. Needed every time this file is used. Generating a new file revokes the previous one."
        ></md-outlined-text-field>
        <md-outlined-text-field
          label="Confirm file passphrase"
          type="password"
          value={confirmPassphrase}
          oninput={(event: Event) => (confirmPassphrase = (event.target as HTMLInputElement).value)}
          style="width: 100%"
        ></md-outlined-text-field>
        {#if passphraseMismatch}
          <div class="notice" role="alert">Passphrases do not match.</div>
        {/if}

      <div class="dialog-actions">
        <md-text-button type="button" onclick={closeMasterKeyDialog}>
          Cancel
        </md-text-button>
        <md-filled-button type="submit" disabled={!canSubmit || app.pending.masterKey}>
          {app.pending.masterKey ? 'Generating...' : 'Generate & download'}
        </md-filled-button>
      </div>
    </form>
  </md-dialog>
{/if}

