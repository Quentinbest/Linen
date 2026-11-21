import { beforeEach, describe, expect, it, vi } from 'vitest'

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }))
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }))

import {
  bookMediaUrl,
  directMediaUrl,
  isTextEntry,
  libraryLoader,
  MAX_TEXT_ENTRY_BYTES,
} from './loader'

describe('§6.4 book media served directly', () => {
  it('encodes the book and entry path into a book-scheme URL', () => {
    expect(bookMediaUrl('b1', 'OEBPS/images/a b#1.png')).toBe(
      'linen-book://localhost/b1/OEBPS/images/a%20b%231.png',
    )
  })

  it('serves images, audio and video directly', () => {
    expect(directMediaUrl('b', 'OEBPS/plate-1.png', 'image/png')).toMatch(/^linen-book:/)
    expect(directMediaUrl('b', 'a/s.mp3', 'audio/mpeg')).toMatch(/^linen-book:/)
  })

  it('keeps documents, styles, SVG and fonts on the sanitised or decoded path', () => {
    for (const [name, type] of [
      ['c.xhtml', 'application/xhtml+xml'],
      ['s.css', 'text/css'],
      ['i.svg', 'image/svg+xml'],
      ['f.otf', 'font/otf'],
      // A manifest that lies about the type does not get the direct path.
      ['c.xhtml', 'image/png'],
    ])
      expect(directMediaUrl('b', name, type)).toBeNull()
  })
})

describe('§7.1, #87 per-entry text size cap', () => {
  beforeEach(() => {
    invokeMock.mockReset()
  })

  it('returns null without invoking IPC when a text entry exceeds 16 MiB', async () => {
    invokeMock.mockImplementation(async (cmd: string, args?: { name?: string }) => {
      if (cmd === 'book_entries') {
        return [
          ['OEBPS/ok.xhtml', 12],
          ['OEBPS/huge.xhtml', MAX_TEXT_ENTRY_BYTES + 1],
          ['OEBPS/huge.css', MAX_TEXT_ENTRY_BYTES + 1],
          ['OEBPS/big-font.otf', MAX_TEXT_ENTRY_BYTES + 1],
        ]
      }
      if (cmd === 'book_entry') {
        return new TextEncoder().encode(args?.name === 'OEBPS/ok.xhtml' ? '<p>ok</p>' : 'bin')
          .buffer
      }
      throw new Error(`unexpected ${cmd}`)
    })

    const loader = await libraryLoader('book-1')
    expect(await loader.loadText('OEBPS/huge.xhtml')).toBeNull()
    expect(await loader.loadBlob('OEBPS/huge.css', 'text/css')).toBeNull()
    expect(invokeMock).toHaveBeenCalledTimes(1) // only book_entries, no book_entry

    expect(await loader.loadText('OEBPS/ok.xhtml')).toBe('<p>ok</p>')
    expect(invokeMock).toHaveBeenLastCalledWith('book_entry', {
      bookId: 'book-1',
      name: 'OEBPS/ok.xhtml',
      text: true,
    })

    const font = await loader.loadBlob('OEBPS/big-font.otf', 'font/otf')
    expect(font).not.toBeNull()
    expect(invokeMock).toHaveBeenLastCalledWith('book_entry', {
      bookId: 'book-1',
      name: 'OEBPS/big-font.otf',
      text: false,
    })
    expect(isTextEntry('OEBPS/noext', 'application/xhtml+xml')).toBe(true)
    expect(isTextEntry('OEBPS/font.otf', 'font/otf')).toBe(false)
  })
})
