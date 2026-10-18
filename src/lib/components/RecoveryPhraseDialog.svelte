<script lang="ts">
  import {
    app,
    cancelRecoveryPhraseSetup,
    confirmRecoveryPhraseSaved,
  } from '../store.svelte';

  let confirmed = $state(false);
  let password = $state('');

  const words = $derived(app.recoveryPhraseReveal?.mnemonic.split(' ') ?? []);

  $effect(() => {
    if (!app.recoveryPhraseReveal) {
      confirmed = false;
      password = '';
    }
  });

  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    void confirmRecoveryPhraseSaved(password, confirmed);
  };
</script>

{#if app.recoveryPhraseReveal}
  <md-dialog
    open
    style="--md-dialog-container-color: var(--md-sys-color-surface-container-high)"
  >
    <div slot="headline">Your recovery phrase</div>
    <form slot="content" class="dialog-body" onsubmit={submit}>
      <div class="notice" role="alert">
        Write these 24 words down on paper, in order, and store them
        somewhere safe and offline. Anyone with this phrase can restore
        access to this vault. xVault shows it only once and never stores it.
      </div>

      <div class="word-grid">
        {#each words as word, index (index)}
          <div class="word-chip">
            <span class="word-chip__index">{index + 1}</span>
            <span class="mono">{word}</span>
          </div>
        {/each}
      </div>

      <label class="checkbox-row">
        <input type="checkbox" bind:checked={confirmed} />
        I have written down these words in a safe, offline place.
      </label>

      <md-outlined-text-field
        label="Current password"
        type="password"
        autocomplete="current-password"
        value={password}
        oninput={(event: Event) => (password = (event.target as HTMLInputElement).value)}
        style="width: 100%"
        supporting-text="Confirms your identity before enabling recovery."
      ></md-outlined-text-field>

      <div class="dialog-actions">
        <md-text-button type="button" onclick={cancelRecoveryPhraseSetup}>
          Cancel
        </md-text-button>
        <md-filled-button
          type="submit"
          disabled={!confirmed || !password || app.pending.recovery}
        >
          {app.pending.recovery ? 'Enabling...' : 'Enable recovery phrase'}
        </md-filled-button>
      </div>
    </form>
  </md-dialog>
{/if}

<style>
  .word-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
  }

  @media (max-width: 520px) {
    .word-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  .word-chip {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: var(--xv-radius-xs);
    background: var(--md-sys-color-surface-container-low);
    border: 1px solid var(--md-sys-color-outline-variant);
  }

  .word-chip__index {
    font-size: 11px;
    color: var(--md-sys-color-on-surface-variant);
    min-width: 18px;
  }

  .checkbox-row {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 14px;
  }
</style>
