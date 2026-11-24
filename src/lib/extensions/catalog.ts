import type { CatalogCategory, CatalogEntryView } from './types'

export const categoryOrder: readonly CatalogCategory[] = [
  'lookup',
  'theme',
  'export',
  'navigation',
  'utility',
]

export interface CatalogFilter {
  query: string
  category: CatalogCategory | 'all'
  showIncompatible: boolean
}

export function filterCatalog(
  entries: readonly CatalogEntryView[],
  filter: CatalogFilter,
): CatalogEntryView[] {
  const q = filter.query.trim().toLowerCase()
  return entries.filter((item) => {
    if (!filter.showIncompatible && item.state.kind === 'incompatible') return false
    if (filter.category !== 'all' && item.entry.category !== filter.category) return false
    if (!q) return true
    const e = item.entry
    return (
      e.name.toLowerCase().includes(q) ||
      e.summary.toLowerCase().includes(q) ||
      e.publisher.toLowerCase().includes(q) ||
      e.category.toLowerCase().includes(q) ||
      e.id.toLowerCase().includes(q) ||
      e.contributesSummary.some((c) => c.toLowerCase().includes(q))
    )
  })
}
