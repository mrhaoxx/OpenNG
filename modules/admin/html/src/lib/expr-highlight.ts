// Expr syntax highlighting for Monaco editor
// Produces inline decorations for expr field values inside YAML

import * as monaco from 'monaco-editor'
import { parseDocument, isMap, isPair, isScalar } from 'yaml'
import type { ExprEnvNode } from './schema'

// ── Token types & patterns ──

type TokenType = 'keyword' | 'string' | 'number' | 'operator' | 'builtin'
  | 'comment' | 'envvar' | 'property' | 'method' | 'predicate'

interface Token {
  start: number // column offset within the line (0-based)
  length: number
  type: TokenType
}

const KEYWORDS = new Set([
  'true', 'false', 'nil',
  'in', 'not', 'and', 'or', 'let',
  'matches', 'contains', 'startsWith', 'endsWith',
])

const BUILTINS = new Set([
  'len', 'type', 'int', 'float', 'string',
  'trim', 'trimPrefix', 'trimSuffix', 'upper', 'lower',
  'split', 'splitAfter', 'replace', 'repeat', 'indexOf', 'lastIndexOf',
  'hasPrefix', 'hasSuffix',
  'all', 'any', 'one', 'none', 'map', 'filter', 'find', 'findIndex',
  'findLast', 'findLastIndex', 'groupBy', 'count', 'concat', 'flatten',
  'uniq', 'join', 'reduce', 'sum', 'mean', 'median',
  'first', 'last', 'take', 'reverse', 'sort', 'sortBy',
  'keys', 'values', 'toPairs', 'fromPairs',
  'max', 'min', 'abs', 'ceil', 'floor', 'round',
  'toJSON', 'fromJSON', 'toBase64', 'fromBase64', 'get',
  'now', 'duration', 'date',
  'bitand', 'bitor', 'bitxor', 'bitnand', 'bitnot', 'bitshl', 'bitshr', 'bitushr',
])

const TOKEN_PATTERNS: [RegExp, TokenType][] = [
  [/\/\/.*$/gm, 'comment'],
  [/\/\*[\s\S]*?\*\//g, 'comment'],
  [/"(?:[^"\\]|\\.)*"/g, 'string'],
  [/'(?:[^'\\]|\\.)*'/g, 'string'],
  [/`[^`]*`/g, 'string'],
  [/\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g, 'number'],
  [/==|!=|>=|<=|&&|\|\||\.\.|\?\?|\?\.|[+\-*/%^<>!]/g, 'operator'],
  [/[;,()[\]{}:?]/g, 'operator'],
]

/** Tokenize a single line of expr code with env-aware coloring. */
function tokenizeLine(line: string, envNames: Set<string>): Token[] {
  const tokens: Token[] = []
  const used = new Uint8Array(line.length)

  for (const [pattern, type] of TOKEN_PATTERNS) {
    pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = pattern.exec(line)) !== null) {
      const start = m.index
      const length = m[0].length
      let overlap = false
      for (let i = start; i < start + length; i++) {
        if (used[i]) { overlap = true; break }
      }
      if (overlap) continue
      tokens.push({ start, length, type })
      for (let i = start; i < start + length; i++) used[i] = 1
    }
  }

  const predRe = /#(?:[a-zA-Z_]\w*)?/g
  let pm: RegExpExecArray | null
  while ((pm = predRe.exec(line)) !== null) {
    const start = pm.index
    const length = pm[0].length
    let overlap = false
    for (let i = start; i < start + length; i++) {
      if (used[i]) { overlap = true; break }
    }
    if (overlap) continue
    tokens.push({ start, length, type: 'predicate' })
    for (let i = start; i < start + length; i++) used[i] = 1
  }

  const wordRe = /\b([a-zA-Z_]\w*)\b/g
  let m: RegExpExecArray | null
  while ((m = wordRe.exec(line)) !== null) {
    const start = m.index
    const word = m[1]
    const length = word.length
    let overlap = false
    for (let i = start; i < start + length; i++) {
      if (used[i]) { overlap = true; break }
    }
    if (overlap) continue

    const afterWord = line.substring(start + length)
    const beforeWord = line.substring(0, start)
    const isAfterDot = beforeWord.endsWith('.')
    const isBeforeParen = /^\s*\(/.test(afterWord)

    let type: TokenType
    if (KEYWORDS.has(word)) {
      type = 'keyword'
    } else if (BUILTINS.has(word) && isBeforeParen) {
      type = 'builtin'
    } else if (isAfterDot && isBeforeParen) {
      type = 'method'
    } else if (isAfterDot) {
      type = 'property'
    } else if (envNames.has(word)) {
      type = 'envvar'
    } else {
      continue
    }

    tokens.push({ start, length, type })
    for (let i = start; i < start + length; i++) used[i] = 1
  }

  return tokens
}

// ── YAML AST-based expr region detection ──

interface ExprRegion {
  startLine: number  // 1-based
  endLine: number    // 1-based, inclusive
  valueCol: number   // 0-based column where the expr value starts
  envNames: Set<string>
}

function envRootNames(env: ExprEnvNode[]): Set<string> {
  return new Set(env.map(n => n.name))
}

function offsetToLine(text: string, offset: number): number {
  let line = 1
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === '\n') line++
  }
  return line
}

function offsetToCol(text: string, offset: number): number {
  let col = 0
  for (let i = offset - 1; i >= 0 && text[i] !== '\n'; i--) {
    col++
  }
  return col
}

/**
 * Find all expr value regions using YAML AST.
 * Walks every map node looking for `kind` + expr field siblings.
 */
export function findExprRegions(
  text: string,
  exprEnvs: Map<string, Map<string, ExprEnvNode[]>>,
): ExprRegion[] {
  if (exprEnvs.size === 0) return []

  const regions: ExprRegion[] = []
  let doc
  try { doc = parseDocument(text) } catch { return [] }

  function walkNode(node: any) {
    if (!node) return
    if (isMap(node)) {
      // Check if this map has a `kind` field
      let kind: string | null = null
      for (const pair of node.items) {
        if (isPair(pair) && isScalar(pair.key) && pair.key.value === 'kind' && isScalar(pair.value)) {
          kind = String(pair.value.value)
          break
        }
      }

      if (kind) {
        const fieldEnvs = exprEnvs.get(kind)
        if (fieldEnvs) {
          // Look for expr fields in this same map
          for (const pair of node.items) {
            if (!isPair(pair) || !isScalar(pair.key)) continue
            const fieldName = String(pair.key.value)
            const env = fieldEnvs.get(fieldName)
            if (!env) continue

            // Found an expr field — get its value range
            const valNode = pair.value as any
            if (!valNode?.range) continue
            const [valStart, , valEnd] = valNode.range
            const startLine = offsetToLine(text, valStart)
            const endLine = offsetToLine(text, valEnd - 1)
            const valueCol = offsetToCol(text, valStart)

            regions.push({
              startLine,
              endLine,
              valueCol,
              envNames: envRootNames(env),
            })
          }
        }
      }

      // Recurse into all values
      for (const pair of node.items) {
        if (isPair(pair)) walkNode(pair.value)
      }
    }
    // Also handle sequences (lists of services, routes, etc.)
    if (node?.items && Symbol.iterator in node.items) {
      for (const item of node.items) {
        if (isMap(item)) walkNode(item)
        else if (isPair(item)) walkNode(item.value)
      }
    }
  }

  walkNode(doc.contents)
  return regions
}

// ── Decoration application ──

const TOKEN_CLASSES: Record<TokenType, string> = {
  keyword:   'expr-kw',
  string:    'expr-str',
  number:    'expr-num',
  operator:  'expr-op',
  builtin:   'expr-fn',
  comment:   'expr-cmt',
  envvar:    'expr-env',
  property:  'expr-prop',
  method:    'expr-meth',
  predicate: 'expr-pred',
}

export function applyExprDecorations(
  editor: monaco.editor.IStandaloneCodeEditor,
  exprEnvs: Map<string, Map<string, ExprEnvNode[]>>,
  oldDecorationIds: string[],
): string[] {
  const model = editor.getModel()
  if (!model) return []

  const text = model.getValue()
  const regions = findExprRegions(text, exprEnvs)
  const decorations: monaco.editor.IModelDeltaDecoration[] = []

  for (const region of regions) {
    for (let lineNum = region.startLine; lineNum <= region.endLine; lineNum++) {
      const lineContent = model.getLineContent(lineNum)

      let exprText: string
      let colOffset: number
      if (lineNum === region.startLine && region.startLine === region.endLine) {
        colOffset = region.valueCol
        exprText = lineContent.substring(colOffset)
      } else {
        const lineIndent = lineContent.search(/\S/)
        if (lineIndent < 0) continue
        colOffset = lineIndent
        exprText = lineContent.substring(colOffset)
      }

      const tokens = tokenizeLine(exprText, region.envNames)
      for (const tok of tokens) {
        const startCol = colOffset + tok.start + 1
        const endCol = startCol + tok.length
        decorations.push({
          range: new monaco.Range(lineNum, startCol, lineNum, endCol),
          options: { inlineClassName: TOKEN_CLASSES[tok.type] },
        })
      }
    }
  }

  return editor.deltaDecorations(oldDecorationIds, decorations) as unknown as string[]
}

// ── CSS injection ──

let cssInjected = false

export function injectExprHighlightCSS() {
  if (cssInjected) return
  cssInjected = true
  const style = document.createElement('style')
  style.textContent = `
    .expr-kw   { color: #c586c0 !important; }
    .expr-str  { color: #ce9178 !important; }
    .expr-num  { color: #b5cea8 !important; }
    .expr-op   { color: #d4d4d4 !important; }
    .expr-fn   { color: #dcdcaa !important; }
    .expr-cmt  { color: #6a9955 !important; font-style: italic; }
    .expr-env  { color: #9cdcfe !important; }
    .expr-prop { color: #4fc1ff !important; }
    .expr-meth { color: #dcdcaa !important; }
    .expr-pred { color: #c586c0 !important; font-weight: bold; }
  `
  document.head.appendChild(style)
}
