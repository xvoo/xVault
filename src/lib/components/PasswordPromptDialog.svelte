<script lang="ts">
  import { app, resolvePasswordPrompt } from '../store.svelte';

  let value = $state('');
  let confirmValue = $state('');

  const prompt = $derived(app.passwordPrompt);

  $effect(() => {
    if (!app.passwordPrompt) {
      value = '';
      confirmValue = '';
    }
  });

  const tooShort = $derived((prompt?.minLength ?? 1) > value.length);
  const mismatch = $derived(!!prompt?.confirm && confirmValue.length > 0 && value !== confirmValue);
  const canSubmit = $derived(!tooShort && (!prompt?.confirm || value === confirmValue));

  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    if (!canSubmit) return;
    resolvePasswordPrompt(value);
  };
</script>

{#if prompt}
  <md-dialog
    open
    onclose={() => resolvePasswordPrompt(null)}
    style="--md-dialog-container-color: var(--md-sys-color-surface-container-high)"
  >
    <div slot="headline">{prompt.title}</div>
    <form slot="content" class="dialog-body" onsubmit={submit}>
      <p class="supporting-text">{prompt.message}</p>
      <md-outlined-text-field
        label={prompt.label}
        type="password"
        autocomplete="off"
        value={value}
        oninput={(event: Event) => (value = (event.target as HTMLInputElement).value)}
        style="width: 100%"
        supporting-text={prompt.minLength ? `At least ${prompt.minLength} characters.` : ''}
      ></md-outlined-text-field>
      {#if prompt.confirm}
        <md-outlined-text-field
          label={`Confirm ${prompt.label.toLowerCase()}`}
          type="password"
          autocomplete="off"
          value={confirmValue}
          oninput={(event: Event) => (confirmValue = (event.target as HTMLInputElement).value)}
          style="width: 100%"
        ></md-outlined-text-field>
        {#if mismatch}
          <div class="notice" role="alert">The two entries do not match.</div>
        {/if}
      {/if}
      <div class="dialog-actions">
        <md-text-button type="button" onclick={() => resolvePasswordPrompt(null)}>Cancel</md-text-button>
        <md-filled-button type="submit" disabled={!canSubmit}>{prompt.submitLabel}</md-filled-button>
      </div>
    </form>
  </md-dialog>
{/if}
