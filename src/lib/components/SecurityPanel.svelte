<script lang="ts">
  import {
    app,
    changeVaultPassword,
    deleteAccountAction,
    disableMasterKeyAction,
    disableRecoveryPhraseAction,
    openMasterKeyDialog,
    previewUniversalImport,
    saveProfile,
    startRecoveryPhraseSetup,
  } from '../store.svelte';

  let name = $state('');
  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let deletePassword = $state('');
  let disableRecoveryPassword = $state('');
  let disableMasterKeyPassword = $state('');
  let importInput: HTMLInputElement | undefined = $state();

  $effect(() => {
    name = app.user?.name ?? 'My Vault';
  });

  const onProfileSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    void saveProfile(name.trim());
  };

  const onPasswordSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    void changeVaultPassword(currentPassword, newPassword, confirmPassword);
    currentPassword = '';
    newPassword = '';
    confirmPassword = '';
  };

  const onDeleteSubmit = (event: SubmitEvent): void => {
    event.preventDefault();
    void deleteAccountAction(deletePassword);
  };

  const onImportChange = async (event: Event): Promise<void> => {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) {
      await previewUniversalImport(file);
    }
    input.value = '';
  };

  const onDisableRecovery = (event: SubmitEvent): void => {
    event.preventDefault();
    void disableRecoveryPhraseAction(disableRecoveryPassword);
    disableRecoveryPassword = '';
  };

  const onDisableMasterKey = (event: SubmitEvent): void => {
    event.preventDefault();
    void disableMasterKeyAction(disableMasterKeyPassword);
    disableMasterKeyPassword = '';
  };

  const setField = (setter: (value: string) => void) => (event: Event) =>
    setter((event.target as HTMLInputElement).value);
</script>

<section class="split-panel">
  <article class="md-card stack-lg">
    <div>
      <p class="eyebrow">Vault identity</p>
      <h3 class="panel-title">Update the name shown in the vault shell.</h3>
    </div>
    <form class="stack-md" onsubmit={onProfileSubmit}>
      <md-outlined-text-field
        label="Vault name"
        value={name}
        oninput={setField((value) => (name = value))}
        style="width: 100%"
      ></md-outlined-text-field>
      <div class="inline-actions">
        <md-filled-button type="submit" disabled={app.pending.profile}>
          {app.pending.profile ? 'Saving...' : 'Save profile'}
        </md-filled-button>
        <span class="supporting-text">
          Username: <span class="mono">{app.user?.loginId ?? 'Unknown'}</span>
        </span>
      </div>
    </form>
  </article>

  <article class="md-card stack-lg">
    <div>
      <p class="eyebrow">Password rotation</p>
      <h3 class="panel-title">Re-encrypt the vault with a new password.</h3>
      <p class="supporting-text">
        Your browser re-wraps the vault key with keys derived from the new
        password. Every other signed-in device is logged out.
      </p>
    </div>
    <form class="stack-md" onsubmit={onPasswordSubmit}>
      <md-outlined-text-field
        label="Current password"
        type="password"
        autocomplete="current-password"
        value={currentPassword}
        oninput={setField((value) => (currentPassword = value))}
        style="width: 100%"
      ></md-outlined-text-field>
      <md-outlined-text-field
        label="New password"
        type="password"
        autocomplete="new-password"
        value={newPassword}
        oninput={setField((value) => (newPassword = value))}
        style="width: 100%"
      ></md-outlined-text-field>
      <md-outlined-text-field
        label="Confirm new password"
        type="password"
        autocomplete="new-password"
        value={confirmPassword}
        oninput={setField((value) => (confirmPassword = value))}
        style="width: 100%"
      ></md-outlined-text-field>
      <div class="inline-actions">
        <md-filled-button type="submit" disabled={app.pending.password}>
          {app.pending.password ? 'Updating...' : 'Change password'}
        </md-filled-button>
      </div>
    </form>
  </article>

  <article class="md-card stack-lg">
    <div>
      <p class="eyebrow">Universal import</p>
      <h3 class="panel-title">Bring in passwords and 2FA secrets from another app.</h3>
      <p class="supporting-text">
        Bitwarden, 1Password (.1pux/.1pif), KeePass (XML), Proton Pass,
        Enpass, Keeper, LastPass, Dashlane, NordPass, RoboForm,
        Chrome/Edge/Firefox/Safari CSV — and Proton Authenticator, Aegis, 2FAS, andOTP, FreeOTP+,
        Raivo, Authenticator Pro, Google Authenticator, Steam (.maFile) or
        any otpauth:// list. Encrypted Aegis, 2FAS, andOTP and Bitwarden
        exports are decrypted locally with their password. Nothing leaves
        your browser unencrypted.
      </p>
    </div>
    <md-outlined-button onclick={() => importInput?.click()} disabled={app.pending.import}>
      <md-icon slot="icon">upload_file</md-icon>
      {app.pending.import ? 'Reading file...' : 'Choose file to import'}
    </md-outlined-button>
  </article>

  <article class="md-card stack-lg">
    <div>
      <p class="eyebrow">Recovery phrase</p>
      <h3 class="panel-title">Restore access without your password.</h3>
      <p class="supporting-text">
        Generates a 24-word phrase that can derive the keys needed to reset
        your password later, if you ever forget it. xVault shows it once and
        never stores it — write it down and keep it offline.
      </p>
    </div>
    {#if app.user?.recoveryEnabled}
      <div class="notice notice--success">Recovery phrase is enabled for this account.</div>
      <form class="stack-md" onsubmit={onDisableRecovery}>
        <md-outlined-text-field
          label="Current password"
          type="password"
          autocomplete="current-password"
          value={disableRecoveryPassword}
          oninput={setField((value) => (disableRecoveryPassword = value))}
          style="width: 100%"
        ></md-outlined-text-field>
        <div class="inline-actions">
          <md-text-button type="submit" disabled={app.pending.recovery}>
            {app.pending.recovery ? 'Disabling...' : 'Disable recovery phrase'}
          </md-text-button>
        </div>
      </form>
    {:else}
      <div class="inline-actions">
        <md-filled-tonal-button onclick={() => void startRecoveryPhraseSetup()}>
          <md-icon slot="icon">key</md-icon>
          Generate recovery phrase
        </md-filled-tonal-button>
      </div>
    {/if}
  </article>

  <article class="md-card stack-lg">
    <div>
      <p class="eyebrow">Master backup file</p>
      <h3 class="panel-title">Last-resort recovery key file.</h3>
      <p class="supporting-text">
        Downloads an encrypted <code class="mono">.key</code> file that can
        restore the entire vault if you lose both your password and your
        recovery phrase. Keep it on offline, physically secure storage.
      </p>
    </div>
    {#if app.user?.masterKeyEnabled}
      <div class="notice notice--success">A master key file is active for this account.</div>
      <form class="stack-md" onsubmit={onDisableMasterKey}>
        <md-outlined-text-field
          label="Current password"
          type="password"
          autocomplete="current-password"
          value={disableMasterKeyPassword}
          oninput={setField((value) => (disableMasterKeyPassword = value))}
          style="width: 100%"
        ></md-outlined-text-field>
        <div class="inline-actions">
          <md-text-button type="submit" disabled={app.pending.masterKey}>
            {app.pending.masterKey ? 'Disabling...' : 'Disable master key file'}
          </md-text-button>
        </div>
      </form>
    {:else}
      <div class="inline-actions">
        <md-filled-tonal-button onclick={openMasterKeyDialog}>
          <md-icon slot="icon">file_download</md-icon>
          Generate recovery key file
        </md-filled-tonal-button>
      </div>
    {/if}
  </article>

  <article class="md-card stack-lg danger-card">
    <div>
      <p class="eyebrow">Destructive action</p>
      <h3 class="panel-title">Delete this account and all encrypted data.</h3>
      <p class="supporting-text">
        This permanently removes the user record and the encrypted vault from
        the server database.
      </p>
    </div>
    <form class="stack-md" onsubmit={onDeleteSubmit}>
      <md-outlined-text-field
        label="Password confirmation"
        type="password"
        autocomplete="current-password"
        value={deletePassword}
        oninput={setField((value) => (deletePassword = value))}
        style="width: 100%"
      ></md-outlined-text-field>
      <md-filled-button
        type="submit"
        class="danger-button"
        disabled={app.pending.danger}
      >
        {app.pending.danger ? 'Deleting account...' : 'Delete account'}
      </md-filled-button>
    </form>
  </article>
</section>

<input
  hidden
  type="file"
  accept=".json,.csv,.txt,.xml,.zip,.1pux,.1pif,.aes,.maFile,.data,application/json,text/csv,text/plain,application/zip,text/xml"
  bind:this={importInput}
  onchange={onImportChange}
/>

<style>
  .panel-title {
    margin: 6px 0 8px;
    font-size: 17px;
    font-weight: 500;
  }

  .danger-card {
    border-color: var(--md-sys-color-error-container);
  }

  .danger-button {
    --md-filled-button-container-color: var(--md-sys-color-error);
    --md-filled-button-label-text-color: var(--md-sys-color-on-error);
  }
</style>
