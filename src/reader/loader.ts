// L17: a foliate-js book loader that reads entries from the core on demand, so a
// large book never crosses into the WebView whole (the §6.4 memory budget).

import { invoke } from '@tauri-apps/api/core'

export interface EntryLoader {
  loadText(name: string): Promise<string | null>
  loadBlob(name: string, type?: string): Promise<Blob | null>
  getSize(name: string): number
  /** §6.4: a URL the app serves a media entry from directly (no blob), or null. */
  urlFor?(name: string, type: string): string | null
}

/** Must match `epub::MAX_TEXT_ENTRY_BYTES` in the core (plan §7.1, #87, 2026-11-21). */
export const MAX_TEXT_ENTRY_BYTES = 16 * 1024 * 1024

/** Must match `epub::is_text_entry` in the core: entries decoded as text or markup. */
export function isTextEntry(name: string, type?: string): boolean {
  if (/\.(xhtml|html?|xml|opf|ncx|css|svg|smil|txt)$/i.test(name)) return true
  if (!type) return false
  const mime = type.split(';')[0].trim().toLowerCase()
  return mime.startsWith('text/') || mime.endsWith('+xml') || mime === 'application/xml'
}

/** Must match `commands::media_type` in the core: the types served on the book scheme. */
const DIRECT_MEDIA = /^(image\/(png|jpeg|gif|webp|avif|bmp)|audio\/|video\/)/

/** The URL of a media entry on the book scheme (`commands::BOOK_SCHEME`). */
/**
 * E6, N6: a book's cover as extracted at import. `version` (the content hash)
 * changes when the file is replaced, so the WebView never shows a stale cover.
 */
export function coverUrl(bookId: string, version: string): string {
  return `linen-book://localhost/_cover/${encodeURIComponent(bookId)}?v=${encodeURIComponent(version)}`
}

export function bookMediaUrl(bookId: string, name: string): string {
  const path = name.split('/').map(encodeURIComponent).join('/')
  return `linen-book://localhost/${encodeURIComponent(bookId)}/${path}`
}

/** The core serves by extension, so both the manifest type and the extension must be media. */
const hasMediaExtension = (name: string) =>
  /\.(png|jpe?g|gif|webp|avif|bmp|mp3|m4a|aac|ogg|oga|opus|wav|flac|mp4|m4v|webm|ogv|mov)$/i.test(
    name,
  )

/** The book-scheme URL for a media entry, or null when it must load as a blob. */
export function directMediaUrl(bookId: string, name: string, type: string): string | null {
  return DIRECT_MEDIA.test(type) && hasMediaExtension(name) ? bookMediaUrl(bookId, name) : null
}

export async function libraryLoader(bookId: string): Promise<EntryLoader> {
  const entries = new Map(await invoke<[string, number][]>('book_entries', { bookId }))
  const bytes = (name: string, text: boolean) =>
    invoke<ArrayBuffer>('book_entry', { bookId, name, text })
  return {
    async loadText(name) {
      const size = entries.get(name)
      // §7.1, #87: skip oversized text chapters before crossing IPC (E3 treats null as damaged).
      if (size === undefined || size > MAX_TEXT_ENTRY_BYTES) return null
      return new TextDecoder().decode(await bytes(name, true))
    },
    async loadBlob(name, type) {
      const size = entries.get(name)
      if (size === undefined) return null
      const text = isTextEntry(name, type)
      if (text && size > MAX_TEXT_ENTRY_BYTES) return null
      return new Blob([await bytes(name, text)], type ? { type } : undefined)
    },
    getSize: (name) => entries.get(name) ?? 0,
    // Images, audio and video load straight from the zip: as blobs, WebKit kept
    // several copies of each in its networking process until a garbage collection.
    urlFor: (name, type) => (entries.has(name) ? directMediaUrl(bookId, name, type) : null),
  }
}
