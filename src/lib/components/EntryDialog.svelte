<script lang="ts">
  import { isMigrationUri, isValidBase32Secret, parseOtpAuthUri, splitEntryName } from '../otpauth';
  import { app, closeEntryDialog, importMigrationQr, saveEntry, showToast } from '../store.svelte';
  import type { OtpAlgorithm, OtpType } from '../types';
  import QrScanner from './QrScanner.svelte';

  const isEditing = $derived(app.entryDialogMode === 'edit');

  let accountName = $state('');
  let issuer = $state('');
  let secret = $state('');
  let digits = $state('6');
  let period = $state('30');
  let otpType = $state<OtpType>('totp');
  let algorithm = $state<OtpAlgorithm>('SHA1');
  let counter = $state('0');
  let folderId = $state('');
  let icon = $state('');
  let isCustomIcon = $state(false);
  let iconFileInput: HTMLInputElement | undefined = $state();

  const closeQrScanner = (): void => {
    app.qrScannerOpen = false;
    app.qrScannerMessage = null;
  };

  const openQrScanner = (): void => {
    app.qrScannerOpen = true;
    app.qrScannerMessage = null;
  };

  const applyQrResult = (text: string): void => {
    try {
      if (isMigrationUri(text)) {
        if (importMigrationQr(text) > 0) {
          closeQrScanner();
          closeEntryDialog();
        }
        return;
      }
      const parsed = parseOtpAuthUri(text);
      if (parsed) {
        accountName = parsed.accountName || accountName;
        issuer = parsed.issuer || issuer;
        secret = parsed.secret;
        digits = String(parsed.digits);
        period = String(parsed.period);
        otpType = parsed.type;
        algorithm = parsed.algorithm;
        counter = String(parsed.counter);
        closeQrScanner();
        showToast('QR code captured — review and save', 'success');
        return;
      }
    } catch (error) {
      app.qrScannerMessage = (error as Error).message;
      return;
    }
    if (isValidBase32Secret(text)) {
      secret = text;
      closeQrScanner();
      showToast('Secret captured — add an account name', 'success');
      return;
    }
    app.qrScannerMessage = 'No OTP secret found in this QR code.';
  };

  const onIconUpload = (event: Event): void => {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) {
      return;
    }
    if (!['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(file.type)) {
      showToast('Please choose a PNG, JPEG, WebP or GIF image.', 'error');
      return;
    }
    if (file.size > 1_000_000) {
      showToast('Image is too large (max 1 MB).', 'error');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      icon = String(reader.result ?? '');
      isCustomIcon = true;
    };
    reader.readAsDataURL(file);
    input.value = '';
  };

  const submit = (): void => {
    saveEntry({
      accountName,
      issuer,
      secret,
      type: otpType,
      algorithm,
      digits: Number(digits) || 6,
      period: Number(period) || 30,
      counter: Number(counter) || 0,
      folderId: folderId || null,
      icon,
      isCustomIcon,
    });
  };

  const setField = (setter: (value: string) => void) => (event: Event) =>
    setter((event.target as HTMLInputElement).value);

  const sortedFolders = $derived(
    app.folders.slice().sort((left, right) => left.name.localeCompare(right.name)),
  );

  // Initialisation du formulaire à l'ouverture du dialogue.
  $effect(() => {
    if (app.entryDialogMode === 'edit' && app.editingEntryId) {
      const entry = app.entries.find((item) => item.id === app.editingEntryId);
      if (entry) {
        const parsed = splitEntryName(entry.name);
        accountName = parsed.title;
        issuer = parsed.subtitle ?? '';
        secret = entry.secret;
        digits = String(entry.digits ?? 6);
        period = String(entry.period ?? 30);
        otpType = entry.type ?? 'totp';
        algorithm = entry.algorithm ?? 'SHA1';
        counter = String(entry.counter ?? 0);
        folderId = entry.folderId ?? '';
        icon = entry.icon ?? '';
        isCustomIcon = entry.isCustomIcon ?? false;
      }
    } else if (app.entryDialogMode === 'create') {
      accountName = '';
      issuer = '';
      secret = '';
      digits = '6';
      period = '30';
      otpType = 'totp';
      algorithm = 'SHA1';
      counter = '0';
      folderId = '';
      icon = '';
      isCustomIcon = false;
    }
  });
</script>

<md-dialog
  open={app.entryDialogMode !== null}
  onclose={closeEntryDialog}
  style="--md-dialog-container-color: var(--md-sys-color-surface-container-high)"
>
  <div slot="headline">
    {isEditing ? 'Edit account' : 'Add account'}
  </div>

  <form
    slot="content"
    class="dialog-body"
    onsubmit={(event) => {
      event.preventDefault();
      submit();
    }}
  >
    {#if app.entryDialogMode === 'create'}
      <md-outlined-text-field
        label="Account name"
        placeholder="GitHub, Google, AWS"
        value={accountName}
        oninput={setField((value) => (accountName = value))}
        style="width: 100%"
      ></md-outlined-text-field>

      <md-outlined-text-field
        label="Secret key or otpauth URI"
        placeholder="JBSWY3DPEHPK3PXP or otpauth://totp/..."
        autocomplete="off"
        value={secret}
        oninput={setField((value) => (secret = value))}
        style="width: 100%"
        supporting-text="Base32 secret, otpauth:// (TOTP, HOTP, Steam) or a Google Authenticator export (otpauth-migration://)."
      ></md-outlined-text-field>
    {/if}

    {#if app.entryDialogMode === 'create'}
      <div class="inline-actions">
        <md-outlined-button onclick={openQrScanner}>
          <md-icon slot="icon">qr_code_scanner</md-icon>
          Scan QR code
        </md-outlined-button>
      </div>
    {:else}
      <div class="field-grid">
        <md-outlined-text-field
          label="Account label"
          placeholder="alice@company.com"
          value={accountName}
          oninput={setField((value) => (accountName = value))}
          style="width: 100%"
        ></md-outlined-text-field>
        <md-outlined-text-field
          label="Issuer"
          placeholder="GitHub, Google, AWS"
          value={issuer}
          oninput={setField((value) => (issuer = value))}
          style="width: 100%"
        ></md-outlined-text-field>
      </div>

      <md-outlined-text-field
        label="Base32 secret"
        placeholder="JBSWY3DPEHPK3PXP"
        autocomplete="off"
        value={secret}
        oninput={setField((value) => (secret = value))}
        style="width: 100%"
      ></md-outlined-text-field>

    {/if}

    {#if !secret.trim().toLowerCase().startsWith('otpauth')}
      <div class="field-grid">
        <md-filled-select
          label="Type"
          value={otpType}
          onchange={(event: Event) => (otpType = (event.target as HTMLInputElement).value as OtpType)}
          style="width: 100%"
        >
          <md-select-option value="totp">TOTP (time-based)</md-select-option>
          <md-select-option value="hotp">HOTP (counter-based)</md-select-option>
          <md-select-option value="steam">Steam Guard</md-select-option>
        </md-filled-select>
        <md-filled-select
          label="Algorithm"
          value={algorithm}
          disabled={otpType === 'steam'}
          onchange={(event: Event) => (algorithm = (event.target as HTMLInputElement).value as OtpAlgorithm)}
          style="width: 100%"
        >
          <md-select-option value="SHA1">SHA-1 (standard)</md-select-option>
          <md-select-option value="SHA256">SHA-256</md-select-option>
          <md-select-option value="SHA512">SHA-512</md-select-option>
        </md-filled-select>
      </div>
      {#if otpType !== 'steam'}
        <div class="field-grid">
          <md-outlined-text-field
            label="Digits"
            type="number"
            min="4"
            max="10"
            value={digits}
            oninput={setField((value) => (digits = value))}
            style="width: 100%"
          ></md-outlined-text-field>
          {#if otpType === 'hotp'}
            <md-outlined-text-field
              label="Counter"
              type="number"
              min="0"
              value={counter}
              oninput={setField((value) => (counter = value))}
              style="width: 100%"
            ></md-outlined-text-field>
          {:else}
            <md-outlined-text-field
              label="Period (seconds)"
              type="number"
              min="1"
              max="3600"
              value={period}
              oninput={setField((value) => (period = value))}
              style="width: 100%"
            ></md-outlined-text-field>
          {/if}
        </div>
      {/if}
    {/if}

    <md-filled-select
      label="Collection"
      value={folderId}
      onchange={(event: Event) =>
        (folderId = (event.target as HTMLInputElement).value)}
      style="width: 100%"
    >
      <md-select-option value="">Ungrouped</md-select-option>
      {#each sortedFolders as folder (folder.id)}
        <md-select-option value={folder.id}>
          {folder.icon ? `${folder.icon}  ` : ''}{folder.name}
        </md-select-option>
      {/each}
    </md-filled-select>

    <div class="icon-editor">
      <div class="icon-preview" aria-hidden="true">
        {#if isCustomIcon && icon.startsWith('data:image/')}
          <img src={icon} alt="" />
        {:else if icon && icon.length <= 2}
          {icon}
        {:else}
          <md-icon>image</md-icon>
        {/if}
      </div>
      <div class="icon-editor__fields">
        <md-outlined-text-field
          label="Marker (emoji)"
          maxlength="2"
          placeholder="•"
          value={icon}
          oninput={setField((value) => (icon = value))}
          style="width: 100%"
          supporting-text="Keep it short, or upload a custom image instead."
        ></md-outlined-text-field>
        <div class="inline-actions">
          <md-outlined-button onclick={() => iconFileInput?.click()}>
            <md-icon slot="icon">upload</md-icon>
            Upload image
          </md-outlined-button>
          {#if isCustomIcon}
            <md-text-button
              onclick={() => {
                icon = '';
                isCustomIcon = false;
              }}
            >
              Clear
            </md-text-button>
          {/if}
        </div>
      </div>
    </div>

    <div class="dialog-actions">
      <md-text-button type="button" onclick={closeEntryDialog}>
        Cancel
      </md-text-button>
      <md-filled-button type="submit">
        {isEditing ? 'Save changes' : 'Add account'}
      </md-filled-button>
    </div>
  </form>
</md-dialog>

{#if app.qrScannerOpen}
  <md-dialog
    open
    onclose={closeQrScanner}
    style="--md-dialog-container-color: var(--md-sys-color-surface-container-high)"
  >
    <div slot="headline">Scan a TOTP QR code</div>
    <div slot="content" class="dialog-body">
      <QrScanner
        onresult={applyQrResult}
        onmessage={(message) => (app.qrScannerMessage = message)}
      />
      <p class="supporting-text">
        {app.qrScannerMessage ??
          'Allow camera access, then align the QR code inside the frame.'}
      </p>
    </div>
    <div slot="actions">
      <md-text-button onclick={closeQrScanner}>Close</md-text-button>
    </div>
  </md-dialog>
{/if}

<input
  hidden
  type="file"
  accept="image/png,image/jpeg,image/webp,image/gif"
  bind:this={iconFileInput}
  onchange={onIconUpload}
/>

<style>
  .icon-editor {
    display: flex;
    gap: 14px;
    align-items: flex-start;
  }

  .icon-editor__fields {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 10px;
    min-width: 0;
  }
</style>
