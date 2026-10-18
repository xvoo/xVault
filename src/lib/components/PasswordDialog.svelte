<script lang="ts">
  import { app, closePasswordDialog, savePasswordEntry } from '../store.svelte';
  import { estimatePasswordStrength, generatePassword } from '../password-generator';

  const isEditing = $derived(app.passwordDialogMode === 'edit');

  let title = $state('');
  let username = $state('');
  let password = $state('');
  let url = $state('');
  let notes = $state('');
  let showPassword = $state(false);
  let showGenerator = $state(false);

  let genLength = $state(20);
  let genUppercase = $state(true);
  let genLowercase = $state(true);
  let genNumbers = $state(true);
  let genSymbols = $state(true);

  const strength = $derived(estimatePasswordStrength(password));

  const strengthLabel: Record<string, string> = {
    weak: 'Weak',
    fair: 'Fair',
    strong: 'Strong',
    excellent: 'Excellent',
  };

  const setField = (setter: (value: string) => void) => (event: Event) =>
    setter((event.target as HTMLInputElement).value);

  const regenerate = (): void => {
    password = generatePassword({
      length: genLength,
      uppercase: genUppercase,
      lowercase: genLowercase,
      numbers: genNumbers,
      symbols: genSymbols,
    });
    showPassword = true;
  };

  const submit = (): void => {
    savePasswordEntry({ title, username, password, url, notes, folderId: null });
  };

  $effect(() => {
    if (app.passwordDialogMode === 'edit' && app.editingPasswordId) {
      const entry = app.passwords.find((item) => item.id === app.editingPasswordId);
      if (entry) {
        title = entry.title;
        username = entry.username;
        password = entry.password;
        url = entry.url ?? '';
        notes = entry.notes ?? '';
      }
    } else if (app.passwordDialogMode === 'create') {
      title = '';
      username = '';
      password = '';
      url = '';
      notes = '';
      showPassword = false;
      showGenerator = false;
    }
  });
</script>

<md-dialog
  open={app.passwordDialogMode !== null}
  onclose={closePasswordDialog}
  style="--md-dialog-container-color: var(--md-sys-color-surface-container-high)"
>
  <div slot="headline">
    {isEditing ? 'Edit password' : 'Add password'}
  </div>

  <form
    slot="content"
    class="dialog-body"
    onsubmit={(event) => {
      event.preventDefault();
      submit();
    }}
  >
    <md-outlined-text-field
      label="Title"
      placeholder="GitHub, Gmail, Bank"
      value={title}
      oninput={setField((value) => (title = value))}
      style="width: 100%"
    ></md-outlined-text-field>

    <md-outlined-text-field
      label="Username or email"
      autocomplete="off"
      value={username}
      oninput={setField((value) => (username = value))}
      style="width: 100%"
    ></md-outlined-text-field>

    <div class="password-field">
      <md-outlined-text-field
        label="Password"
        type={showPassword ? 'text' : 'password'}
        autocomplete="new-password"
        value={password}
        oninput={setField((value) => (password = value))}
        style="width: 100%"
      >
        <md-icon-button
          slot="trailingicon"
          aria-label={showPassword ? 'Hide password' : 'Show password'}
          onclick={() => (showPassword = !showPassword)}
        >
          <md-icon>{showPassword ? 'visibility_off' : 'visibility'}</md-icon>
        </md-icon-button>
      </md-outlined-text-field>
      <div class="inline-actions">
        <span class="badge" class:badge--error={strength === 'weak'}>
          {password ? strengthLabel[strength] : 'No password'}
        </span>
        <md-text-button type="button" onclick={() => (showGenerator = !showGenerator)}>
          <md-icon slot="icon">autorenew</md-icon>
          Generator
        </md-text-button>
      </div>
    </div>

    {#if showGenerator}
      <div class="generator-box stack-md">
        <div class="field-grid">
          <label class="checkbox-row">
            <input type="checkbox" bind:checked={genUppercase} /> Uppercase (A-Z)
          </label>
          <label class="checkbox-row">
            <input type="checkbox" bind:checked={genLowercase} /> Lowercase (a-z)
          </label>
          <label class="checkbox-row">
            <input type="checkbox" bind:checked={genNumbers} /> Numbers (0-9)
          </label>
          <label class="checkbox-row">
            <input type="checkbox" bind:checked={genSymbols} /> Symbols (!@#$)
          </label>
        </div>
        <label class="length-row">
          <span>Length: {genLength}</span>
          <input type="range" min="8" max="128" bind:value={genLength} />
        </label>
        <md-filled-tonal-button type="button" onclick={regenerate}>
          <md-icon slot="icon">autorenew</md-icon>
          Generate password
        </md-filled-tonal-button>
      </div>
    {/if}

    <md-outlined-text-field
      label="URL"
      placeholder="https://example.com"
      value={url}
      oninput={setField((value) => (url = value))}
      style="width: 100%"
    ></md-outlined-text-field>

    <md-outlined-text-field
      label="Notes"
      type="textarea"
      rows="3"
      value={notes}
      oninput={setField((value) => (notes = value))}
      style="width: 100%"
    ></md-outlined-text-field>

    <div class="dialog-actions">
      <md-text-button type="button" onclick={closePasswordDialog}>
        Cancel
      </md-text-button>
      <md-filled-button type="submit">
        {isEditing ? 'Save changes' : 'Add password'}
      </md-filled-button>
    </div>
  </form>
</md-dialog>

<style>
  .password-field {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .generator-box {
    background: var(--md-sys-color-surface-container-low);
    border-radius: var(--xv-radius-sm);
    padding: 14px;
  }

  .checkbox-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--md-sys-color-on-surface-variant);
  }

  .length-row {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 13px;
    color: var(--md-sys-color-on-surface-variant);
  }

  .length-row input[type='range'] {
    width: 100%;
  }
</style>
