<script lang="ts">
  import {
    copyPasswordField,
    deletePasswordEntry,
    openPasswordDialog,
  } from '../store.svelte';
  import type { PasswordEntry } from '../types';

  let { entry }: { entry: PasswordEntry } = $props();

  let revealed = $state(false);

  const maskedPassword = $derived('•'.repeat(Math.min(entry.password.length || 8, 16)));
</script>

<div class="password-card">
  <div class="password-card__header">
    <div class="avatar avatar--sm" aria-hidden="true">
      <span class="avatar__fallback">{entry.title.trim().slice(0, 1).toUpperCase() || 'P'}</span>
    </div>
    <div class="password-card__identity" title={entry.title}>
      <h3>{entry.title}</h3>
      {#if entry.username}
        <p class="supporting-text">{entry.username}</p>
      {/if}
    </div>
  </div>

  <div class="password-card__field">
    <span class="meta-row">
      <span>Password</span>
    </span>
    <div class="password-card__value">
      <code class="mono">{revealed ? entry.password : maskedPassword}</code>
      <md-icon-button
        aria-label={revealed ? 'Hide password' : 'Show password'}
        onclick={() => (revealed = !revealed)}
      >
        <md-icon>{revealed ? 'visibility_off' : 'visibility'}</md-icon>
      </md-icon-button>
    </div>
  </div>

  {#if entry.url}
    <p class="supporting-text password-card__url" title={entry.url}>{entry.url}</p>
  {/if}

  <div class="password-card__footer inline-actions">
    <md-text-button
      onclick={() => void copyPasswordField(entry.username, 'Username')}
      disabled={!entry.username}
    >
      <md-icon slot="icon">person</md-icon>
      Copy user
    </md-text-button>
    <md-text-button onclick={() => void copyPasswordField(entry.password, 'Password')}>
      <md-icon slot="icon">content_copy</md-icon>
      Copy password
    </md-text-button>
    <div class="inline-actions inline-actions--end" style="margin-left: auto">
      <md-icon-button
        aria-label={`Edit ${entry.title}`}
        onclick={() => openPasswordDialog('edit', entry.id)}
      >
        <md-icon>edit</md-icon>
      </md-icon-button>
      <md-icon-button
        aria-label={`Delete ${entry.title}`}
        onclick={() => deletePasswordEntry(entry.id)}
      >
        <md-icon>delete</md-icon>
      </md-icon-button>
    </div>
  </div>
</div>

<style>
  .password-card {
    background: var(--md-sys-color-surface-container);
    border: 1px solid var(--md-sys-color-outline-variant);
    border-radius: var(--xv-radius-md);
    padding: 18px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .password-card__header {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .password-card__identity {
    flex: 1;
    min-width: 0;
  }

  .password-card__identity h3 {
    margin: 0;
    font-size: 15px;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .password-card__identity p {
    margin: 2px 0 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .password-card__value {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    background: var(--md-sys-color-surface-container-low);
    border-radius: var(--xv-radius-sm);
    padding: 6px 6px 6px 14px;
  }

  .password-card__value code {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    letter-spacing: 0.04em;
  }

  .password-card__url {
    margin: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .password-card__footer {
    flex-wrap: wrap;
  }
</style>
