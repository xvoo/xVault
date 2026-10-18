<script lang="ts">
  import { app, getVisiblePasswords, openPasswordDialog } from '../store.svelte';
  import PasswordCard from './PasswordCard.svelte';

  const visiblePasswords = $derived(getVisiblePasswords());
</script>

<section class="passwords-layout">
  <md-outlined-text-field
    id="password-search"
    label="Quick search"
    placeholder="Search by title, username, or URL"
    value={app.passwordSearch}
    oninput={(event: Event) =>
      (app.passwordSearch = (event.target as HTMLInputElement).value)}
    style="width: 100%"
  >
    <md-icon slot="leadingicon">search</md-icon>
    {#if app.passwordSearch}
      <md-icon-button
        slot="trailingicon"
        aria-label="Clear search"
        onclick={() => (app.passwordSearch = '')}
      >
        <md-icon>close</md-icon>
      </md-icon-button>
    {/if}
  </md-outlined-text-field>

  {#if app.passwords.length === 0}
    <div class="empty-state">
      <md-icon class="empty-state__icon">password</md-icon>
      <p class="eyebrow">Vault ready</p>
      <h2>No passwords stored yet.</h2>
      <p class="supporting-text">
        Save a login manually, or import an existing password manager export
        from the Security tab.
      </p>
      <div class="inline-actions" style="margin-top: 12px">
        <md-filled-button onclick={() => openPasswordDialog('create')}>
          Add first password
        </md-filled-button>
      </div>
    </div>
  {:else if visiblePasswords.length === 0}
    <div class="empty-state">
      <md-icon class="empty-state__icon">search_off</md-icon>
      <p class="eyebrow">No match</p>
      <h2>Your search returned zero passwords.</h2>
    </div>
  {:else}
    <div class="otp-grid">
      {#each visiblePasswords as entry (entry.id)}
        <PasswordCard {entry} />
      {/each}
    </div>
  {/if}
</section>

<style>
  .passwords-layout {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .empty-state__icon {
    font-size: 40px;
    color: var(--md-sys-color-on-surface-variant);
  }
</style>
