// The core's view of an extension (src-tauri/src/extensions): its manifest (P1)
// and its state in this library.

/** SB4 (API 1.2): the icons a lookup may name; Linen draws them (`components/icons.ts`). */
export type LookupIcon = 'lightbulb'

export interface ExtensionManifest {
  id: string
  version: string
  name: string
  description: string
  publisher?: string | null
  engines: { linen: string }
  main?: string | null
  activation: string[]
  contributes: {
    commands: { id: string; title: string }[]
    selectionActions: { command: string; when?: string | null }[]
    navigatorTabs: { id: string; title: string; page: string }[]
    themes: {
      id: string
      title: string
      scheme: 'light' | 'dark'
      tokens: Record<string, string>
    }[]
    exporters: { id: string; title: string; command: string }[]
    /** API 1.1, experimental (Reading Lens LK1). Older manifests from the core may lack it. */
    /** SB4 (API 1.2): `icon` names one Linen draws, for the lookup's button on the bar. */
    lookups?: { id: string; title: string; when?: string | null; icon?: LookupIcon | null }[]
    /** API 1.1, experimental (LK8): an options page, opened from Settings. */
    options?: { page: string } | null
  }
  permissions: string[]
  /** API 1.1, experimental (LK6): hosts asked for later, one at a time. */
  optionalPermissions?: string[]
}

export interface InstalledExtension {
  manifest: ExtensionManifest
  enabled: boolean
  granted: string[]
  builtin: boolean
  incompatible: string | null
  suspended: boolean
  crashes: number[]
}

export interface Inspection {
  manifest: ExtensionManifest
  permissions: {
    permission: string
    consent: 'atInstall' | 'highlighted' | 'stronglyWarned' | 'eachUse'
  }[]
  update_from: string | null
  new_permissions: string[]
  incompatible: string | null
}

export type CatalogCategory = 'lookup' | 'theme' | 'export' | 'navigation' | 'utility'

export interface CatalogEntry {
  id: string
  name: string
  summary: string
  publisher: string
  homepage: string
  category: CatalogCategory
  version: string
  enginesLinen: string
  downloadUrl: string
  sha256: string
  sizeBytes: number
  permissions: string[]
  optionalPermissions: string[]
  contributesSummary: string[]
}

export type EntryInstallState =
  | { kind: 'notInstalled' }
  | { kind: 'installedCurrent' }
  | { kind: 'updateAvailable'; installedVersion: string }
  | { kind: 'incompatible'; reason: string }

export interface CatalogEntryView {
  entry: CatalogEntry
  state: EntryInstallState
}

export interface CatalogResponse {
  entries: CatalogEntryView[]
  fetchedAt: number
  offline: boolean
  stale: boolean
}

export interface StagedInspection {
  token: string
  inspection: Inspection
}

export type CatalogRowState =
  | { kind: 'idle' }
  | { kind: 'downloading' }
  | { kind: 'confirming'; token: string }
  | { kind: 'installing' }
  | { kind: 'failed'; reason: string }
