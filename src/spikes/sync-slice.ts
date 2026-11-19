// SD4: removed in Stage 2/3.
import { invoke } from '@tauri-apps/api/core'
import { openView, painted, type Criterion, type SpikeResult } from './common'

const BOOK = 'standardebooks-moby-dick.epub'

interface Snapshot {
  configured: boolean
  position?: [string, number] | null
  annotations?: { id: string; cfi_range: string; quote_exact: string; note: string | null }[]
}

function call(action: { kind: string } & Record<string, unknown>): Promise<Snapshot> {
  return invoke('spike_sync_slice', { action })
}

export async function spikeSync(): Promise<SpikeResult> {
  const criteria: Criterion[] = []
  const check = (id: string, description: string, ok: boolean, evidence: string) => {
    criteria.push({ id, description, verdict: ok ? 'pass' : 'fail', evidence })
  }
  const a = await call({ kind: 'pass', side: 0 })
  const b = await call({ kind: 'pass', side: 1 })
  check(
    'SY-nothing-without-setup',
    'No test library or sync folder opens before setup',
    !a.configured && !b.configured,
    'Both passes returned unconfigured before either root was created.',
  )
  try {
    await call({ kind: 'setup' })
    const { view } = await openView(BOOK)
    await painted()
    const start = view.lastLocation?.cfi
    if (!start) throw new Error('Fixture start was not reported')
    const startIndex = view.resolveCFI(start).index
    const index = view.book.sections.findIndex(
      (section, i) => i > startIndex && section.linear !== 'no' && section.size > 4000,
    )
    if (index < 0) throw new Error('Fixture has no suitable section')
    await view.goTo(index)
    await painted()
    const location = view.lastLocation
    const doc = view.renderer.getContents().find((contents) => contents.index === index)?.doc
    const paragraph = doc?.querySelector('p')
    if (!location || !doc || !paragraph) throw new Error('Fixture page did not open')
    const walker = doc.createTreeWalker(paragraph, NodeFilter.SHOW_TEXT)
    let textNode = walker.nextNode() as Text | null
    while (textNode && !textNode.data.trim()) textNode = walker.nextNode() as Text | null
    if (!textNode) throw new Error('Fixture paragraph has no text node')
    const range = doc.createRange()
    range.setStart(textNode, 0)
    range.setEnd(textNode, Math.min(textNode.length, 32))
    const cfiRange = view.getCFI(index, range)
    const quote = range.toString()
    if (!quote.trim()) throw new Error('Fixture paragraph is empty')
    await call({
      kind: 'save',
      cfi: location.cfi,
      fraction: location.fraction,
      range: cfiRange,
      quote,
    })
    const initial = (await call({ kind: 'read', side: 0 })).annotations?.[0]
    view.close()
    await call({ kind: 'pass', side: 0 })
    await call({ kind: 'pass', side: 1 })
    const received = await call({ kind: 'read', side: 1 })
    const cfi = received.position?.[0]
    const { view: resumed } = await openView(BOOK, { lastLocation: cfi })
    await painted()
    const resumedCfi = resumed.lastLocation?.cfi
    const note = received.annotations?.[0]
    const reopened = note ? resumed.resolveCFI(note.cfi_range) : undefined
    const noteDoc = resumed.renderer
      .getContents()
      .find((contents) => contents.index === reopened?.index)?.doc
    const noteText =
      noteDoc && reopened ? (reopened.anchor(noteDoc) as Range).toString() : undefined
    check(
      'SY-place-resume',
      'Reopen the EPUB in B at the position saved in A',
      cfi === location.cfi &&
        Math.abs((received.position?.[1] ?? -1) - location.fraction) < 1e-9 &&
        resumedCfi === location.cfi,
      `Saved ${location.cfi} (${location.fraction}), received ${cfi} (${received.position?.[1]}), reopened ${resumedCfi}.`,
    )
    resumed.close()
    await call({ kind: 'edit', note: 'edited in B' })
    await call({ kind: 'pass', side: 1 })
    await call({ kind: 'pass', side: 0 })
    const roundTrip = (await call({ kind: 'read', side: 0 })).annotations?.[0]
    check(
      'SY-highlight-roundtrip',
      'Apply the highlight in B and return its edited note to A',
      !!initial &&
        note?.id === initial.id &&
        note?.quote_exact === quote &&
        noteText === quote &&
        note?.note === 'made in A' &&
        roundTrip?.id === initial.id &&
        roundTrip?.note === 'edited in B',
      `Anchor resolves to the original quote: ${noteText === quote}. B received “${note?.note}”, A received “${roundTrip?.note}”.`,
    )
  } finally {
    await call({ kind: 'reset' })
  }
  return { spike: 'sync', criteria, raw: {} }
}
