<script lang="ts">
  import { app, cancelUniversalImport, confirmUniversalImport } from '../store.svelte';

  const preview = $derived(app.importPreview);
</script>

{#if preview}
  <md-dialog
    open
    onclose={cancelUniversalImport}
    style="--md-dialog-container-color: var(--md-sys-color-surface-container-high)"
  >
    <div slot="headline">Review import</div>
    <div slot="content" class="dialog-body">
      <p class="supporting-text">
        Detected format: <strong>{preview.sourceFormat}</strong>
      </p>

      <div class="summary-grid">
        <div class="summary-cell">
          <span class="summary-cell__value">{preview.passwords.length}</span>
          <span class="eyebrow">Passwords</span>
        </div>
        <div class="summary-cell">
          <span class="summary-cell__value">{preview.totps.length}</span>
          <span class="eyebrow">2FA codes</span>
        </div>
        {#if preview.skipped > 0}
          <div class="summary-cell summary-cell--muted">
            <span class="summary-cell__value">{preview.skipped}</span>
            <span class="eyebrow">Skipped rows</span>
          </div>
        {/if}
      </div>

      <p class="supporting-text">
        These items will be added to your vault alongside what's already
        there — nothing existing is overwritten or removed.
      </p>

      <div class="dialog-actions">
        <md-text-button type="button" onclick={cancelUniversalImport}>
          Cancel
        </md-text-button>
        <md-filled-button type="button" onclick={confirmUniversalImport}>
          Import {preview.passwords.length + preview.totps.length} item{preview.passwords.length + preview.totps.length === 1 ? '' : 's'}
        </md-filled-button>
      </div>
    </div>
  </md-dialog>
{/if}

<style>
  .summary-grid {
    display: flex;
    gap: 12px;
  }

  .summary-cell {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    padding: 14px;
    border-radius: var(--xv-radius-sm);
    background: var(--md-sys-color-surface-container-low);
  }

  .summary-cell--muted {
    opacity: 0.7;
  }

  .summary-cell__value {
    font-size: 22px;
    font-weight: 600;
  }
</style>
