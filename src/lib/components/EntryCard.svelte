<script lang="ts">
  import { splitEntryName } from '../otpauth';
  import {
    advanceHotp,
    app,
    copyCode,
    deleteEntry,
    openEntryDialog,
  } from '../store.svelte';
  import { clampDigits, clampPeriod, generateOtp, getTimeRemaining } from '../totp';
  import type { TOTPEntry } from '../types';

  let { entry }: { entry: TOTPEntry } = $props();

  const type = $derived(entry.type ?? 'totp');
  const isHotp = $derived(type === 'hotp');
  const period = $derived(clampPeriod(entry.period));
  const digits = $derived(clampDigits(entry.digits, type));
  const parsed = $derived(splitEntryName(entry.name));

  let code = $state('------');
  let remaining = $state(0);
  let copied = $derived(app.copiedEntryId === entry.id);
  let lastBucket = -1;

  const formatCode = (value: string): string => {
    if (value.length < 6 || !/^\d+$/.test(value)) {
      return value;
    }
    const half = Math.ceil(value.length / 2);
    return `${value.slice(0, half)} ${value.slice(half)}`;
  };

  const compute = async (): Promise<void> => {
    try {
      code = await generateOtp(entry.secret, {
        type,
        algorithm: entry.algorithm,
        digits,
        period,
        counter: entry.counter,
      });
    } catch {
      code = '-'.repeat(digits);
    }
  };

  const tick = async (): Promise<void> => {
    const bucket = Math.floor(Date.now() / 1000 / period);
    remaining = getTimeRemaining(period);
    if (bucket !== lastBucket) {
      lastBucket = bucket;
      await compute();
    }
  };

  $effect(() => {
    // Recompute whenever the entry's parameters change.
    void entry.secret, entry.algorithm, entry.counter, digits, period, type;
    lastBucket = -1;
    if (isHotp) {
      void compute();
      return;
    }
    void tick();
    const interval = setInterval(() => void tick(), 500);
    return () => clearInterval(interval);
  });
</script>

<div
  class="otp-card"
  role="button"
  tabindex="0"
  onclick={() => void copyCode(entry, code)}
  onkeydown={(event: KeyboardEvent) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      void copyCode(entry, code);
    }
  }}
>
  <div class="otp-card__header">
    <div class="avatar" aria-hidden="true">
      {#if entry.isCustomIcon && entry.icon.startsWith('data:image/')}
        <img class="avatar__image" src={entry.icon} alt="" />
      {:else if (entry.icon ?? '').trim().length > 0 && (entry.icon ?? '').trim().length <= 2}
        <span>{entry.icon.trim()}</span>
      {:else}
        <span class="avatar__fallback">
          {entry.name.trim().slice(0, 1).toUpperCase() || 'X'}
        </span>
      {/if}
    </div>
    <div class="otp-card__identity" title={entry.name}>
      <p class="eyebrow">{parsed.subtitle ?? 'Stored account'}</p>
      <h3>{parsed.title}</h3>
    </div>
    <span class="badge">{isHotp ? `#${entry.counter ?? 0}` : type === 'steam' ? 'Steam' : `${period}s`}</span>
  </div>

  <div>
    <p class="meta-row">
      <span>Current code</span>
      <span>
        {#if isHotp}
          {digits} digits · counter {entry.counter ?? 0}
        {:else if type === 'steam'}
          Steam Guard · {period}s cycle
        {:else}
          {digits} digits · {period}s cycle{entry.algorithm && entry.algorithm !== 'SHA1' ? ` · ${entry.algorithm}` : ''}
        {/if}
      </span>
    </p>
    <strong class="otp-card__code" aria-label={`Current code for ${entry.name}`}>
      {formatCode(code)}
    </strong>
  </div>

  <div class="otp-card__footer">
    {#if isHotp}
      <div class="inline-actions">
        <md-text-button
          onclick={(event: MouseEvent) => {
            event.stopPropagation();
            advanceHotp(entry.id);
          }}
        >
          <md-icon slot="icon">skip_next</md-icon>
          Next code
        </md-text-button>
      </div>
    {:else}
      <div class="meta-row">
        <span>Refresh in</span>
        <span class="mono">{remaining}s</span>
      </div>
      <md-linear-progress value={remaining / period} aria-label="Time until code refresh"></md-linear-progress>
    {/if}

    <div class="inline-actions inline-actions--end">
      <md-text-button
        onclick={(event: MouseEvent) => {
          event.stopPropagation();
          void copyCode(entry, code);
        }}
      >
        <md-icon slot="icon">{copied ? 'check' : 'content_copy'}</md-icon>
        {copied ? 'Copied' : 'Copy'}
      </md-text-button>
      <md-icon-button
        aria-label={`Edit ${entry.name}`}
        onclick={(event: MouseEvent) => {
          event.stopPropagation();
          openEntryDialog('edit', entry.id);
        }}
      >
        <md-icon>edit</md-icon>
      </md-icon-button>
      <md-icon-button
        aria-label={`Delete ${entry.name}`}
        onclick={(event: MouseEvent) => {
          event.stopPropagation();
          deleteEntry(entry.id);
        }}
      >
        <md-icon>delete</md-icon>
      </md-icon-button>
    </div>
  </div>
</div>
