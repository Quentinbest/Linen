<script lang="ts">
  // Settings › Extensions (Screen 11; P5, P6, P7) and the install sheet (G1,
  // provisional). Installed extensions with what they can access and what they add,
  // their switch, a quiet failure box with Restart and Disable, Remove (asking about
  // their data), pinning in the reader's ⋯ menu, and Restart without extensions.
  import { invoke } from '@tauri-apps/api/core'
  import { emit } from '@tauri-apps/api/event'
  import { open } from '@tauri-apps/plugin-dialog'
  import { onMount } from 'svelte'
  import Icon from '../components/Icon.svelte'
  import Modal from '../components/Modal.svelte'
  import { t } from '../lib/strings'
  import { ipc } from '../app/ipc'
  import { testHooks } from '../app/testHooks'
  import { contributionLabels, permissionLabel } from '../lib/extensions/labels'
  import { categoryOrder, filterCatalog } from '../lib/extensions/catalog'
  import type {
    CatalogCategory,
    CatalogEntry,
    CatalogResponse,
    CatalogRowState,
    Inspection,
    InstalledExtension,
    StagedInspection,
  } from '../lib/extensions/types'
  import OptionsDialog from './OptionsDialog.svelte'
  import { THEMES, type Theme } from '../lib/theme/tokens'

  let list = $state<InstalledExtension[]>([])
  let safeMode = $state(false)
  let pinned = $state<string[]>([])
  let tab = $state<'installed' | 'browse'>('installed')
  let catalog = $state<CatalogResponse | null>(null)
  let catalogLoading = $state(false)
  let catalogError = $state<string | null>(null)
  let query = $state('')
  let category = $state<CatalogCategory | 'all'>('all')
  let showIncompatible = $state(false)
  let rowStates = $state<Record<string, CatalogRowState>>({})
  let sheet = $state<{
    path?: string
    catalogToken?: string
    catalogId?: string
    inspection: Inspection
  } | null>(null)
  let error = $state<{ name: string; reason: string } | null>(null)
  let removing = $state<InstalledExtension | null>(null)
  let status = $state('')
  /** LK8: the extension whose options page is open. */
  let optionsFor = $state<InstalledExtension | null>(null)
  /** The style kit's colours for an options page: the reader's theme. */
  let theme = $state<Theme>(THEMES.paper)
  let installedTabEl = $state<HTMLButtonElement | null>(null)
  let browseTabEl = $state<HTMLButtonElement | null>(null)
  let destroyed = false
  let catalogReqSeq = 0
  let stagingSeq = 0

  const filteredCatalog = $derived(
    catalog ? filterCatalog(catalog.entries, { query, category, showIncompatible }) : [],
  )
  const rowStateOf = (id: string): CatalogRowState => rowStates[id] ?? { kind: 'idle' }
  const setRowState = (id: string, next: CatalogRowState) => {
    rowStates = { ...rowStates, [id]: next }
  }
  const optional = (x: InstalledExtension) =>
    x.granted.filter(
      (p) => p.startsWith('network:') && (x.manifest.optionalPermissions ?? []).includes(p),
    )
  async function revoke(x: InstalledExtension, host: string) {
    await invoke('extension_revoke', { id: x.manifest.id, host })
    await changed()
  }
  /** Opened from the peek's “Open options” (settings.html#options=<id>, or an event). */
  export function openOptions(id: string) {
    const x = list.find((e) => e.manifest.id === id)
    if (x?.manifest.contributes.options) {
      tab = 'installed'
      optionsFor = x
    }
  }

  async function reload() {
    list = await invoke<InstalledExtension[]>('extensions_list')
  }
  /** The reader's window reloads its extensions. */
  async function changed() {
    await reload()
    await emit('extensions-changed')
    if (catalog) void loadCatalog(false)
  }

  async function loadCatalog(force: boolean) {
    const seq = ++catalogReqSeq
    catalogLoading = true
    catalogError = null
    try {
      const next = await invoke<CatalogResponse>('extension_catalog_list', { force })
      if (destroyed || seq !== catalogReqSeq) return
      catalog = next
    } catch (e) {
      if (destroyed || seq !== catalogReqSeq) return
      catalogError = String((e as { message?: string }).message ?? e)
    } finally {
      if (!destroyed && seq === catalogReqSeq) {
        catalogLoading = false
      }
    }
  }

  function selectTab(next: 'installed' | 'browse') {
    tab = next
    if (next === 'browse' && !catalog && !catalogLoading) {
      void loadCatalog(false)
    }
  }

  function onTabKeydown(e: KeyboardEvent) {
    let next: 'installed' | 'browse' | null = null
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      next = tab === 'installed' ? 'browse' : 'installed'
    } else if (e.key === 'Home') {
      next = 'installed'
    } else if (e.key === 'End') {
      next = 'browse'
    }
    if (!next) return
    e.preventDefault()
    selectTab(next)
    ;(next === 'installed' ? installedTabEl : browseTabEl)?.focus()
  }

  function discardCurrentSheetToken() {
    const prev = sheet
    if (prev?.catalogToken) {
      void invoke('extension_catalog_discard', { token: prev.catalogToken })
      if (prev.catalogId) setRowState(prev.catalogId, { kind: 'idle' })
    }
  }

  async function stageCatalogEntry(entry: CatalogEntry) {
    const seq = ++stagingSeq
    setRowState(entry.id, { kind: 'downloading' })
    try {
      const staged = await invoke<StagedInspection>('extension_catalog_stage', { id: entry.id })
      if (destroyed || seq !== stagingSeq) {
        void invoke('extension_catalog_discard', { token: staged.token })
        if (!destroyed) setRowState(entry.id, { kind: 'idle' })
        return
      }
      if (staged.inspection.incompatible) {
        await invoke('extension_catalog_discard', { token: staged.token })
        if (destroyed) return
        setRowState(entry.id, { kind: 'failed', reason: staged.inspection.incompatible })
        error = { name: staged.inspection.manifest.name, reason: staged.inspection.incompatible }
        return
      }
      discardCurrentSheetToken()
      setRowState(entry.id, { kind: 'confirming', token: staged.token })
      sheet = {
        catalogToken: staged.token,
        catalogId: entry.id,
        inspection: staged.inspection,
      }
    } catch (e) {
      if (destroyed) return
      if (seq !== stagingSeq) {
        setRowState(entry.id, { kind: 'idle' })
        return
      }
      setRowState(entry.id, {
        kind: 'failed',
        reason: String((e as { message?: string }).message ?? e),
      })
    }
  }

  async function closeSheet() {
    const current = sheet
    sheet = null
    if (current?.catalogToken) {
      await invoke('extension_catalog_discard', { token: current.catalogToken })
      if (!destroyed && current.catalogId) setRowState(current.catalogId, { kind: 'idle' })
    }
  }

  async function pickFile() {
    // The e2e harness cannot drive the open dialog; it hands over a path instead.
    const path = testHooks?.pickExtensionFile
      ? await testHooks.pickExtensionFile()
      : await open({ filters: [{ name: t.extSettings.fileFilter, extensions: ['linenext'] }] })
    if (typeof path !== 'string' || destroyed) return
    try {
      const inspection = await invoke<Inspection>('extension_inspect', { path })
      if (destroyed) return
      if (inspection.incompatible) {
        error = { name: inspection.manifest.name, reason: inspection.incompatible }
        return
      }
      stagingSeq++
      discardCurrentSheetToken()
      sheet = { path, inspection }
    } catch (e) {
      if (destroyed) return
      error = {
        name: path.split('/').pop() ?? path,
        reason: String((e as { message?: string }).message ?? e),
      }
    }
  }

  async function install() {
    if (!sheet) return
    const { path, catalogToken, catalogId, inspection } = sheet
    sheet = null
    if (catalogToken) {
      if (catalogId) setRowState(catalogId, { kind: 'installing' })
      try {
        await invoke('extension_catalog_install', {
          token: catalogToken,
          granted: inspection.manifest.permissions,
        })
        if (catalogId) setRowState(catalogId, { kind: 'idle' })
        status = t.extSettings.installed(inspection.manifest.name)
        await changed()
      } catch (e) {
        const reason = String((e as { message?: string }).message ?? e)
        if (catalogId) setRowState(catalogId, { kind: 'failed', reason })
        error = { name: inspection.manifest.name, reason }
      }
      return
    }
    if (!path) return
    await invoke('extension_install', { path, granted: inspection.manifest.permissions })
    status = t.extSettings.installed(inspection.manifest.name)
    await changed()
  }

  async function setEnabled(x: InstalledExtension, enabled: boolean) {
    await invoke('extension_set_enabled', { id: x.manifest.id, enabled })
    await changed()
  }

  async function restart(x: InstalledExtension) {
    await invoke('extension_restart', { id: x.manifest.id })
    await changed()
  }

  async function remove(deleteData: boolean) {
    const x = removing
    removing = null
    if (!x) return
    await invoke('extension_remove', { id: x.manifest.id, deleteData })
    pinned = pinned.filter((id) => id !== x.manifest.id)
    await ipc.settingSet('pinnedExtensions', JSON.stringify(pinned))
    await changed()
  }

  async function togglePin(x: InstalledExtension) {
    const id = x.manifest.id
    pinned = pinned.includes(id) ? pinned.filter((p) => p !== id) : [...pinned, id]
    await ipc.settingSet('pinnedExtensions', JSON.stringify(pinned))
    await emit('extensions-changed')
  }

  const kind = (x: InstalledExtension) =>
    x.builtin
      ? t.extSettings.builtin
      : x.manifest.contributes.themes.length && !x.manifest.main
        ? t.extSettings.themePack
        : null
  const recentFailures = (x: InstalledExtension) =>
    x.crashes.filter((c) => Date.now() - c < 24 * 3600 * 1000).length

  onMount(() => {
    void ipc.settingGet('theme').then((v) => {
      const dark = matchMedia('(prefers-color-scheme: dark)').matches
      theme =
        v === 'night'
          ? THEMES.night
          : v === 'sepia'
            ? THEMES.sepia
            : v === 'paper' || !dark
              ? THEMES.paper
              : THEMES.night
    })
    void reload()
    void invoke<boolean>('app_safe_mode').then((v) => (safeMode = v))
    void ipc.settingGet('pinnedExtensions').then((v) => (pinned = JSON.parse(v ?? '[]')))
    return () => {
      destroyed = true
      if (sheet?.catalogToken) {
        void invoke('extension_catalog_discard', { token: sheet.catalogToken })
      }
    }
  })
</script>

<div class="head">
  <p class="intro">{t.prefs.extensionsIntro}</p>
  <button type="button" class="btn" onclick={() => void pickFile()}>{t.extSettings.install}</button>
</div>
<div class="subbar">
  <div class="segmented" role="tablist" aria-label={t.extSettings.catalog.tabsLabel}>
    <button
      bind:this={installedTabEl}
      id="ext-tab-installed"
      type="button"
      role="tab"
      class="seg"
      aria-selected={tab === 'installed'}
      aria-controls="ext-panel-installed"
      tabindex={tab === 'installed' ? 0 : -1}
      onkeydown={onTabKeydown}
      onclick={() => selectTab('installed')}>{t.extSettings.catalog.tabInstalled}</button
    >
    <button
      bind:this={browseTabEl}
      id="ext-tab-browse"
      type="button"
      role="tab"
      class="seg"
      aria-selected={tab === 'browse'}
      aria-controls="ext-panel-browse"
      tabindex={tab === 'browse' ? 0 : -1}
      onkeydown={onTabKeydown}
      onclick={() => selectTab('browse')}>{t.extSettings.catalog.tabBrowse}</button
    >
  </div>
</div>
{#if safeMode}<p class="banner" role="status">{t.extSettings.safeMode}</p>{/if}
{#if status}<p class="status" role="status">{status}</p>{/if}

<div
  class="tabpanel"
  role="tabpanel"
  id={tab === 'installed' ? 'ext-panel-installed' : 'ext-panel-browse'}
  aria-labelledby={tab === 'installed' ? 'ext-tab-installed' : 'ext-tab-browse'}
>
  {#if tab === 'installed'}
    <ul class="list">
      {#each list as x (x.manifest.id)}
        {@const m = x.manifest}
        {@const themeOnly = m.contributes.themes.length > 0 && !m.main}
        <li class="ext" data-extension={m.id}>
          <span class="icon" aria-hidden="true">{m.name.slice(0, 1)}</span>
          <div class="body">
            <div class="title-row">
              <span class="name" translate="no">{m.name}</span>
              <span class="meta"
                >{[kind(x), m.version, x.enabled ? null : t.extSettings.off]
                  .filter(Boolean)
                  .join(' · ')}</span
              >
              <span class="grow"></span>
              <button
                type="button"
                role="switch"
                class="switch"
                aria-checked={x.enabled}
                aria-label={t.extSettings.enabled(m.name)}
                disabled={!!x.incompatible}
                onclick={() => void setEnabled(x, !x.enabled)}><span class="thumb"></span></button
              >
            </div>
            {#if m.description}<p class="description" translate="no">{m.description}</p>{/if}
            {#if themeOnly}
              <p class="chips">
                <span class="label">{t.extSettings.adds}</span><span class="chip"
                  >{t.extSettings.themesAdded(1)}</span
                >
                <span class="label">{t.extSettings.can}</span><span class="plain"
                  >{t.extSettings.nothing}</span
                >
              </p>
            {:else}
              <p class="chips">
                <span class="label">{t.extSettings.canAccess}</span>
                {#each m.permissions as p (p)}
                  {@const l = permissionLabel(p)}
                  <span class="chip" class:warn={l.warn || l.network}
                    >{#if l.network}<Icon name="globe" size={12} />{/if}{l.label}</span
                  >
                {:else}
                  <span class="plain">{t.extSettings.noAccess}</span>
                {/each}
              </p>
              {#if optional(x).length}
                <!-- EP4, LK6 (Canvas 12): each host the reader allowed, with Remove. -->
                <p class="chips" data-sends-to>
                  <span class="label">{t.extAccess.sendsTo}</span>
                  {#each optional(x) as p (p)}
                    {@const host = p.slice('network:'.length)}
                    <span class="chip warn"><Icon name="globe" size={12} />{host}</span>
                    <span class="plain">{t.extAccess.sendsWhat} ·</span>
                    <button
                      type="button"
                      class="link"
                      aria-label={t.extAccess.removeHost(host)}
                      onclick={() => void revoke(x, host)}>{t.extAccess.remove}</button
                    >
                  {/each}
                </p>
              {/if}
              {#if contributionLabels(m).length}
                <p class="chips">
                  <span class="label">{t.extSettings.adds}</span>
                  {#each contributionLabels(m) as a (a)}<span class="chip">{a}</span>{/each}
                </p>
              {/if}
            {/if}
            {#if x.incompatible}
              <p class="failure">
                <Icon name="warning" size={14} />{t.extSettings.incompatible(x.incompatible)}
              </p>
            {:else if x.suspended || recentFailures(x)}
              <div class="failure" role="status">
                <Icon name="warning" size={14} />
                <span class="grow"
                  >{x.suspended
                    ? t.extSettings.suspended
                    : t.extSettings.failures(recentFailures(x))}</span
                >
                <button type="button" class="btn small" onclick={() => void restart(x)}
                  >{t.extSettings.restart}</button
                >
                <button type="button" class="btn small" onclick={() => void setEnabled(x, false)}
                  >{t.extSettings.disable}</button
                >
              </div>
            {/if}
            {#if !x.builtin || m.contributes.commands.length || m.contributes.options}
              <p class="actions">
                {#if m.contributes.commands.length}
                  <label class="pin"
                    ><input
                      type="checkbox"
                      checked={pinned.includes(m.id)}
                      onchange={() => void togglePin(x)}
                    />{t.extSettings.pin}</label
                  >
                {/if}
                {#if m.contributes.options && x.enabled && !x.incompatible}
                  <button
                    type="button"
                    class="link"
                    data-options-button
                    onclick={() => (optionsFor = x)}>{t.extAccess.options}</button
                  >
                {/if}
                {#if !x.builtin}
                  <button type="button" class="link" onclick={() => (removing = x)}
                    >{t.extSettings.remove}</button
                  >
                {/if}
              </p>
            {/if}
          </div>
        </li>
      {/each}
    </ul>

    <div class="foot">
      <button type="button" class="btn" onclick={() => void invoke('app_restart_safe')}
        >{t.extSettings.restartWithout}</button
      >
      <span class="help">{t.extSettings.shiftHint}</span>
    </div>
  {:else}
    <div class="catalog-controls">
      <input
        type="search"
        class="search"
        bind:value={query}
        aria-label={t.extSettings.catalog.searchLabel}
        placeholder={t.extSettings.catalog.searchPlaceholder}
      />
      <button
        type="button"
        class="btn small"
        disabled={catalogLoading}
        onclick={() => void loadCatalog(true)}
      >
        {catalogLoading ? t.extSettings.catalog.refreshing : t.extSettings.catalog.refresh}
      </button>
    </div>
    <div class="pills-row">
      <div class="pills">
        <button
          type="button"
          class="pill"
          class:active={category === 'all'}
          aria-pressed={category === 'all'}
          onclick={() => (category = 'all')}>{t.extSettings.catalog.categories.all}</button
        >
        {#each categoryOrder as cat (cat)}
          <button
            type="button"
            class="pill"
            class:active={category === cat}
            aria-pressed={category === cat}
            onclick={() => (category = cat)}>{t.extSettings.catalog.categories[cat]}</button
          >
        {/each}
      </div>
      <label class="pin">
        <input type="checkbox" bind:checked={showIncompatible} />{t.extSettings.catalog
          .showIncompatible}
      </label>
    </div>

    {#if catalog && (catalog.offline || catalog.stale)}
      <p class="banner" role="status">{t.extSettings.catalog.offlineBanner}</p>
    {/if}

    {#if catalogError}
      <div class="failure" role="status">
        <Icon name="warning" size={14} />
        <span class="grow">{t.extSettings.catalog.loadFailed} {catalogError}</span>
        <button type="button" class="btn small" onclick={() => void loadCatalog(true)}
          >{t.extSettings.catalog.retry}</button
        >
      </div>
    {/if}

    {#if catalogLoading && !catalog}
      <p class="plain" role="status">{t.extSettings.catalog.loading}</p>
    {:else if !catalog && catalogError}
      <!-- Error banner rendered above. -->
    {:else if filteredCatalog.length === 0}
      <p class="plain">{t.extSettings.catalog.empty}</p>
    {:else}
      <ul class="list">
        {#each filteredCatalog as item (item.entry.id)}
          {@const e = item.entry}
          {@const rs = rowStateOf(e.id)}
          <li class="ext" data-catalog-extension={e.id}>
            <span class="icon" aria-hidden="true">{e.name.slice(0, 1)}</span>
            <div class="body">
              <div class="title-row">
                <span class="name" translate="no">{e.name}</span>
                <span class="meta">
                  {[
                    t.extSettings.catalog.categories[e.category],
                    e.version,
                    t.extSettings.catalog.byPublisher(e.publisher),
                  ].join(' · ')}
                </span>
                <span class="grow"></span>
                {#if item.state.kind === 'incompatible'}
                  <span class="plain">{t.extSettings.catalog.incompatibleBadge}</span>
                {:else if item.state.kind === 'installedCurrent'}
                  <span class="plain">{t.extSettings.catalog.installedBadge}</span>
                {:else if rs.kind === 'downloading'}
                  <button type="button" class="btn small" disabled
                    >{t.extSettings.catalog.downloading}</button
                  >
                {:else if rs.kind === 'installing'}
                  <button type="button" class="btn small" disabled
                    >{t.extSettings.catalog.installing}</button
                  >
                {:else if item.state.kind === 'updateAvailable'}
                  <button
                    type="button"
                    class="btn small primary"
                    disabled={rs.kind === 'confirming'}
                    onclick={() => void stageCatalogEntry(e)}>{t.extSettings.update}</button
                  >
                {:else}
                  <button
                    type="button"
                    class="btn small primary"
                    disabled={rs.kind === 'confirming'}
                    onclick={() => void stageCatalogEntry(e)}>{t.extSettings.catalog.get}</button
                  >
                {/if}
              </div>
              <p class="description" translate="no">{e.summary}</p>
              {#if item.state.kind === 'updateAvailable'}
                <p class="plain">{t.extSettings.catalog.updateFrom(item.state.installedVersion)}</p>
              {/if}
              {#if e.permissions.length}
                <p class="chips">
                  <span class="label">{t.extSettings.canAccess}</span>
                  {#each e.permissions as p (p)}
                    {@const l = permissionLabel(p)}
                    <span class="chip" class:warn={l.warn || l.network}
                      >{#if l.network}<Icon name="globe" size={12} />{/if}{l.label}</span
                    >
                  {/each}
                </p>
              {/if}
              {#if e.contributesSummary.length}
                <p class="chips">
                  <span class="label">{t.extSettings.adds}</span>
                  {#each e.contributesSummary as c (c)}<span class="chip" translate="no">{c}</span
                    >{/each}
                </p>
              {/if}
              {#if item.state.kind === 'incompatible'}
                <p class="failure">
                  <Icon name="warning" size={14} />{item.state.reason}
                </p>
              {:else if rs.kind === 'failed'}
                <p class="failure" role="status">
                  <Icon name="warning" size={14} />{rs.reason}
                </p>
              {/if}
              <p class="actions">
                <button
                  type="button"
                  class="link"
                  onclick={() => void invoke('open_external', { url: e.homepage })}
                  >{t.extSettings.catalog.website}</button
                >
              </p>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</div>

{#if optionsFor}
  <OptionsDialog
    extension={optionsFor}
    {theme}
    onclose={() => (optionsFor = null)}
    onchanged={async () => {
      await changed()
      return list.find((e) => e.manifest.id === optionsFor?.manifest.id)
    }}
  />
{/if}

<!-- G1: the install sheet (provisional). -->
<Modal
  label={sheet
    ? sheet.inspection.update_from
      ? t.extSettings.updateTitle(sheet.inspection.manifest.name, sheet.inspection.manifest.version)
      : t.extSettings.installTitle(sheet.inspection.manifest.name)
    : ''}
  open={sheet !== null}
  onclose={() => void closeSheet()}
  width={480}
>
  {#if sheet}
    {@const i = sheet.inspection}
    {@const shown = i.update_from ? i.new_permissions : i.manifest.permissions}
    <div class="sheet" data-install-sheet>
      <h2>
        {i.update_from
          ? t.extSettings.updateTitle(i.manifest.name, i.manifest.version)
          : t.extSettings.installTitle(i.manifest.name)}
      </h2>
      <p class="meta">
        {i.manifest.version}{i.manifest.publisher ? ` · ${i.manifest.publisher}` : ''}
      </p>
      {#if i.manifest.description}<p>{i.manifest.description}</p>{/if}
      <p class="unverified"><Icon name="warning" size={14} />{t.extSettings.notVerified}</p>
      <h3>{i.update_from ? t.extSettings.newAccess : t.extSettings.canAccess}</h3>
      {#if shown.length}
        <ul class="perms">
          {#each shown as p (p)}
            {@const l = permissionLabel(p)}
            <li class:warn={l.warn}>{l.label}</li>
          {/each}
        </ul>
      {:else}
        <p class="plain">{t.extSettings.noAccess}</p>
      {/if}
      {#if !i.update_from && contributionLabels(i.manifest).length}
        <h3>{t.extSettings.adds}</h3>
        <p>{contributionLabels(i.manifest).join(' · ')}</p>
      {/if}
      <div class="buttons">
        <button type="button" class="btn" onclick={() => void closeSheet()}
          >{i.update_from ? t.extSettings.keepCurrent : t.extSettings.cancel}</button
        >
        <button type="button" class="btn primary" onclick={() => void install()}
          >{i.update_from ? t.extSettings.update : t.extSettings.installButton}</button
        >
      </div>
    </div>
  {/if}
</Modal>

<Modal
  label={error ? t.extSettings.cantInstall(error.name) : ''}
  open={error !== null}
  onclose={() => (error = null)}
  width={440}
>
  {#if error}
    <div class="sheet" data-install-error>
      <h2>{t.extSettings.cantInstall(error.name)}</h2>
      <p>{error.reason}</p>
      <div class="buttons">
        <button type="button" class="btn primary" onclick={() => (error = null)}
          >{t.extSettings.close}</button
        >
      </div>
    </div>
  {/if}
</Modal>

<Modal
  label={removing ? t.extSettings.removeTitle(removing.manifest.name) : ''}
  open={removing !== null}
  onclose={() => (removing = null)}
  width={440}
>
  {#if removing}
    <div class="sheet" data-remove-sheet>
      <h2>{t.extSettings.removeTitle(removing.manifest.name)}</h2>
      <p>{t.extSettings.removeBody}</p>
      <div class="buttons">
        <button type="button" class="btn" onclick={() => (removing = null)}
          >{t.extSettings.cancel}</button
        >
        <button type="button" class="btn" onclick={() => void remove(false)}
          >{t.extSettings.keepData}</button
        >
        <button type="button" class="btn primary" onclick={() => void remove(true)}
          >{t.extSettings.deleteData}</button
        >
      </div>
    </div>
  {/if}
</Modal>

<style>
  .head {
    display: flex;
    align-items: flex-start;
    gap: 24px;
  }
  .subbar {
    display: flex;
    align-items: center;
  }
  .segmented {
    display: inline-flex;
    padding: 2px;
    border-radius: 8px;
    background: var(--control-track);
    box-shadow: inset 0 0 0 1px var(--segment-ring);
  }
  .tabpanel {
    display: contents;
  }
  .seg {
    height: 28px;
    padding: 0 14px;
    border: 0;
    border-radius: 6px;
    background: transparent;
    color: var(--track-ink);
    font: 500 13px var(--font-ui);
  }
  .seg[aria-selected='true'] {
    background: var(--raised);
    color: var(--ink);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.12);
  }
  .catalog-controls {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .search {
    flex: 1;
    height: 30px;
    padding: 0 10px;
    border: 1px solid var(--popover-border);
    border-radius: 8px;
    background: var(--raised);
    color: var(--ink);
    font: 400 13px var(--font-ui);
  }
  .pills-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }
  .pills {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .pill {
    height: 26px;
    padding: 0 10px;
    border: 1px solid var(--popover-border);
    border-radius: 13px;
    background: var(--raised);
    color: var(--ink-secondary);
    font: 500 12px var(--font-ui);
  }
  .pill.active {
    background: var(--ink);
    border-color: var(--ink);
    color: var(--ground);
  }
  .seg:focus-visible,
  .pill:focus-visible,
  .search:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .intro {
    flex: 1;
    margin: 0;
    font-size: 13px;
    line-height: 1.5;
    color: var(--ink);
  }
  .banner,
  .status {
    margin: 0;
    font-size: 13px;
  }
  .banner {
    padding: 10px 12px;
    border-radius: 8px;
    background: var(--control-track);
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    border-top: 1px solid var(--hairline);
  }
  .ext {
    display: flex;
    gap: 16px;
    padding: 18px 0;
    border-bottom: 1px solid var(--hairline);
  }
  .icon {
    width: 40px;
    height: 40px;
    flex-shrink: 0;
    display: grid;
    place-items: center;
    border-radius: 10px;
    background: var(--control-track);
    color: var(--ink-secondary);
    font: 500 17px var(--font-reading, Literata, Georgia, serif);
  }
  .body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .title-row {
    display: flex;
    align-items: baseline;
    gap: 8px;
  }
  .name {
    font-size: 15px;
    font-weight: 600;
  }
  .meta {
    font-size: 12px;
    color: var(--ink-secondary);
  }
  .grow {
    flex: 1;
  }
  .description,
  .chips,
  .actions {
    margin: 0;
    font-size: 13px;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .label {
    font-size: 12px;
    font-weight: 600;
    margin-right: 4px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 9px;
    border-radius: 12px;
    background: var(--control-track);
    font-size: 12px;
  }
  .chip.warn {
    background: color-mix(in srgb, var(--accent) 14%, transparent);
    color: var(--accent);
  }
  .plain {
    font-size: 12px;
    color: var(--ink-secondary);
  }
  .failure {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 0;
    padding: 10px 12px;
    border-radius: 8px;
    background: color-mix(in srgb, var(--accent) 8%, var(--ground));
    font-size: 13px;
  }
  .actions {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .pin {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
  }
  .link {
    border: 0;
    padding: 0;
    background: none;
    color: var(--accent);
    font: 500 12px var(--font-ui);
  }
  .foot {
    display: flex;
    align-items: center;
    gap: 12px;
    padding-top: 16px;
  }
  .help {
    font-size: 12px;
    color: var(--ink-secondary);
  }
  .btn {
    height: 32px;
    padding: 0 14px;
    border: 1px solid var(--popover-border);
    border-radius: 8px;
    background: var(--raised);
    color: var(--ink);
    font: 500 13px var(--font-ui);
    white-space: nowrap;
  }
  .btn.small {
    height: 28px;
  }
  .btn.primary {
    background: var(--ink);
    border-color: var(--ink);
    color: var(--ground);
    font-weight: 600;
  }
  .switch {
    width: 38px;
    height: 22px;
    padding: 2px;
    border: 0;
    border-radius: 11px;
    background: var(--control-track);
    box-shadow: inset 0 0 0 1px var(--segment-ring);
  }
  .switch .thumb {
    display: block;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--raised);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
    transition: transform 120ms;
  }
  .switch[aria-checked='true'] {
    background: var(--accent);
    box-shadow: none;
  }
  .switch[aria-checked='true'] .thumb {
    transform: translateX(16px);
  }
  .btn:focus-visible,
  .switch:focus-visible,
  .link:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  .sheet {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 8px 4px;
    font-family: var(--font-ui);
    color: var(--ink);
  }
  .sheet h2 {
    margin: 0;
    font-size: 17px;
  }
  .sheet h3 {
    margin: 8px 0 0;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--ink-secondary);
  }
  .sheet p {
    margin: 0;
    font-size: 13px;
    line-height: 1.5;
  }
  .unverified {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--ink-secondary);
  }
  .perms {
    margin: 0;
    padding-left: 18px;
    font-size: 13px;
    line-height: 1.6;
  }
  .perms .warn {
    color: var(--accent);
    font-weight: 600;
  }
  .buttons {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 8px;
  }
</style>
