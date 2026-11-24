import { describe, expect, it } from 'vitest'
import { categoryOrder, filterCatalog } from './catalog'
import type { CatalogCategory, CatalogEntryView, EntryInstallState } from './types'

function makeItem(
  overrides: Partial<CatalogEntryView['entry']> & {
    id: string
    name: string
    category: CatalogCategory
  },
  state: EntryInstallState = { kind: 'notInstalled' },
): CatalogEntryView {
  return {
    entry: {
      summary: 'A helpful extension.',
      publisher: 'Example Studio',
      homepage: 'https://example.org',
      version: '1.0.0',
      enginesLinen: '^1.0',
      downloadUrl: 'https://example.org/ext.linenext',
      sha256: 'a'.repeat(64),
      sizeBytes: 1024,
      permissions: [],
      optionalPermissions: [],
      contributesSummary: [],
      ...overrides,
    },
    state,
  }
}

const FIXTURE: CatalogEntryView[] = [
  makeItem({
    id: 'org.example.wiktionary',
    name: 'Wiktionary Lookup',
    summary: 'Look up words in Wiktionary.',
    publisher: 'Lexicon Guild',
    category: 'lookup',
  }),
  makeItem({
    id: 'org.example.nord',
    name: 'Nord Theme',
    summary: 'Arctic inspired dark palette.',
    publisher: 'Frost Works',
    category: 'theme',
  }),
  makeItem(
    {
      id: 'org.example.future',
      name: 'Future Exporter',
      summary: 'Requires Linen API 2.0.',
      publisher: 'NextGen',
      category: 'export',
    },
    { kind: 'incompatible', reason: 'requires API ^2.0' },
  ),
]

describe('filterCatalog', () => {
  it('exposes categories in stable display order', () => {
    expect(categoryOrder).toEqual(['lookup', 'theme', 'export', 'navigation', 'utility'])
  })

  it('hides incompatible entries by default and shows them when toggled', () => {
    const hidden = filterCatalog(FIXTURE, {
      query: '',
      category: 'all',
      showIncompatible: false,
    })
    expect(hidden.map((x) => x.entry.id)).toEqual(['org.example.wiktionary', 'org.example.nord'])

    const shown = filterCatalog(FIXTURE, {
      query: '',
      category: 'all',
      showIncompatible: true,
    })
    expect(shown.map((x) => x.entry.id)).toEqual([
      'org.example.wiktionary',
      'org.example.nord',
      'org.example.future',
    ])
  })

  it('filters by category', () => {
    const themes = filterCatalog(FIXTURE, {
      query: '',
      category: 'theme',
      showIncompatible: true,
    })
    expect(themes.map((x) => x.entry.id)).toEqual(['org.example.nord'])
  })

  it('matches query against name, summary, publisher, and category case-insensitively', () => {
    const byName = filterCatalog(FIXTURE, {
      query: 'WIKTIONARY',
      category: 'all',
      showIncompatible: true,
    })
    expect(byName.map((x) => x.entry.id)).toEqual(['org.example.wiktionary'])

    const bySummary = filterCatalog(FIXTURE, {
      query: 'arctic',
      category: 'all',
      showIncompatible: true,
    })
    expect(bySummary.map((x) => x.entry.id)).toEqual(['org.example.nord'])

    const byPublisher = filterCatalog(FIXTURE, {
      query: 'lexicon guild',
      category: 'all',
      showIncompatible: true,
    })
    expect(byPublisher.map((x) => x.entry.id)).toEqual(['org.example.wiktionary'])

    const byCategory = filterCatalog(FIXTURE, {
      query: 'export',
      category: 'all',
      showIncompatible: true,
    })
    expect(byCategory.map((x) => x.entry.id)).toEqual(['org.example.future'])
  })
})
