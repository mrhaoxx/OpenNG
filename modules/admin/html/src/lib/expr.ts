// Expr autocomplete utilities

import type { ExprEnvNode } from './schema'

export interface ExprCompletion {
  label: string
  type: string
  kind: 'field' | 'method' | 'keyword' | 'function'
  insertText: string
}

// ── Built-in functions & keywords from expr-lang ──

interface BuiltinDef {
  label: string
  type: string
  kind: 'function' | 'keyword'
  insertText: string
}

const BUILTINS: BuiltinDef[] = [
  // String functions
  { label: 'trim',        type: '(str, chars?) string',          kind: 'function', insertText: 'trim(' },
  { label: 'trimPrefix',  type: '(str, prefix) string',          kind: 'function', insertText: 'trimPrefix(' },
  { label: 'trimSuffix',  type: '(str, suffix) string',          kind: 'function', insertText: 'trimSuffix(' },
  { label: 'upper',       type: '(str) string',                  kind: 'function', insertText: 'upper(' },
  { label: 'lower',       type: '(str) string',                  kind: 'function', insertText: 'lower(' },
  { label: 'split',       type: '(str, delim, n?) []string',     kind: 'function', insertText: 'split(' },
  { label: 'splitAfter',  type: '(str, delim, n?) []string',     kind: 'function', insertText: 'splitAfter(' },
  { label: 'replace',     type: '(str, old, new) string',        kind: 'function', insertText: 'replace(' },
  { label: 'repeat',      type: '(str, n) string',               kind: 'function', insertText: 'repeat(' },
  { label: 'indexOf',     type: '(str, substr) int',             kind: 'function', insertText: 'indexOf(' },
  { label: 'lastIndexOf', type: '(str, substr) int',             kind: 'function', insertText: 'lastIndexOf(' },
  { label: 'hasPrefix',   type: '(str, prefix) bool',            kind: 'function', insertText: 'hasPrefix(' },
  { label: 'hasSuffix',   type: '(str, suffix) bool',            kind: 'function', insertText: 'hasSuffix(' },

  // Collection functions
  { label: 'all',           type: '(array, predicate) bool',       kind: 'function', insertText: 'all(' },
  { label: 'any',           type: '(array, predicate) bool',       kind: 'function', insertText: 'any(' },
  { label: 'one',           type: '(array, predicate) bool',       kind: 'function', insertText: 'one(' },
  { label: 'none',          type: '(array, predicate) bool',       kind: 'function', insertText: 'none(' },
  { label: 'map',           type: '(array, predicate) array',      kind: 'function', insertText: 'map(' },
  { label: 'filter',        type: '(array, predicate) array',      kind: 'function', insertText: 'filter(' },
  { label: 'find',          type: '(array, predicate) any',        kind: 'function', insertText: 'find(' },
  { label: 'findIndex',     type: '(array, predicate) int',        kind: 'function', insertText: 'findIndex(' },
  { label: 'findLast',      type: '(array, predicate) any',        kind: 'function', insertText: 'findLast(' },
  { label: 'findLastIndex',  type: '(array, predicate) int',       kind: 'function', insertText: 'findLastIndex(' },
  { label: 'groupBy',       type: '(array, predicate) map',        kind: 'function', insertText: 'groupBy(' },
  { label: 'count',         type: '(array, predicate?) int',       kind: 'function', insertText: 'count(' },
  { label: 'concat',        type: '(array, ...arrays) array',      kind: 'function', insertText: 'concat(' },
  { label: 'flatten',       type: '(array) array',                 kind: 'function', insertText: 'flatten(' },
  { label: 'uniq',          type: '(array) array',                 kind: 'function', insertText: 'uniq(' },
  { label: 'join',          type: '(array, delim?) string',        kind: 'function', insertText: 'join(' },
  { label: 'reduce',        type: '(array, predicate, init?) any', kind: 'function', insertText: 'reduce(' },
  { label: 'sum',           type: '(array, predicate?) number',    kind: 'function', insertText: 'sum(' },
  { label: 'mean',          type: '(array) float',                 kind: 'function', insertText: 'mean(' },
  { label: 'median',        type: '(array) float',                 kind: 'function', insertText: 'median(' },
  { label: 'first',         type: '(array) any',                   kind: 'function', insertText: 'first(' },
  { label: 'last',          type: '(array) any',                   kind: 'function', insertText: 'last(' },
  { label: 'take',          type: '(array, n) array',              kind: 'function', insertText: 'take(' },
  { label: 'reverse',       type: '(array) array',                 kind: 'function', insertText: 'reverse(' },
  { label: 'sort',          type: '(array, order?) array',         kind: 'function', insertText: 'sort(' },
  { label: 'sortBy',        type: '(array, predicate, order?) array', kind: 'function', insertText: 'sortBy(' },

  // Map functions
  { label: 'keys',   type: '(map) []string', kind: 'function', insertText: 'keys(' },
  { label: 'values', type: '(map) []any',    kind: 'function', insertText: 'values(' },

  // Number functions
  { label: 'max',   type: '(a, b) number', kind: 'function', insertText: 'max(' },
  { label: 'min',   type: '(a, b) number', kind: 'function', insertText: 'min(' },
  { label: 'abs',   type: '(n) number',    kind: 'function', insertText: 'abs(' },
  { label: 'ceil',  type: '(n) int',       kind: 'function', insertText: 'ceil(' },
  { label: 'floor', type: '(n) int',       kind: 'function', insertText: 'floor(' },
  { label: 'round', type: '(n) int',       kind: 'function', insertText: 'round(' },

  // Type functions
  { label: 'len',        type: '(v) int',       kind: 'function', insertText: 'len(' },
  { label: 'type',       type: '(v) string',    kind: 'function', insertText: 'type(' },
  { label: 'int',        type: '(v) int',       kind: 'function', insertText: 'int(' },
  { label: 'float',      type: '(v) float',     kind: 'function', insertText: 'float(' },
  { label: 'string',     type: '(v) string',    kind: 'function', insertText: 'string(' },
  { label: 'toJSON',     type: '(v) string',    kind: 'function', insertText: 'toJSON(' },
  { label: 'fromJSON',   type: '(str) any',     kind: 'function', insertText: 'fromJSON(' },
  { label: 'toBase64',   type: '(v) string',    kind: 'function', insertText: 'toBase64(' },
  { label: 'fromBase64', type: '(str) string',  kind: 'function', insertText: 'fromBase64(' },
  { label: 'toPairs',    type: '(map) []array', kind: 'function', insertText: 'toPairs(' },
  { label: 'fromPairs',  type: '(pairs) map',   kind: 'function', insertText: 'fromPairs(' },
  { label: 'get',        type: '(v, key) any',  kind: 'function', insertText: 'get(' },

  // Date/time functions
  { label: 'now',      type: '() time.Time',       kind: 'function', insertText: 'now()' },
  { label: 'duration', type: '(str) time.Duration', kind: 'function', insertText: 'duration(' },
  { label: 'date',     type: '(str, fmt?, tz?) time.Time', kind: 'function', insertText: 'date(' },

  // Bitwise functions
  { label: 'bitand',  type: '(a, b) int', kind: 'function', insertText: 'bitand(' },
  { label: 'bitor',   type: '(a, b) int', kind: 'function', insertText: 'bitor(' },
  { label: 'bitxor',  type: '(a, b) int', kind: 'function', insertText: 'bitxor(' },
  { label: 'bitnand', type: '(a, b) int', kind: 'function', insertText: 'bitnand(' },
  { label: 'bitnot',  type: '(a) int',    kind: 'function', insertText: 'bitnot(' },
  { label: 'bitshl',  type: '(a, b) int', kind: 'function', insertText: 'bitshl(' },
  { label: 'bitshr',  type: '(a, b) int', kind: 'function', insertText: 'bitshr(' },
  { label: 'bitushr', type: '(a, b) int', kind: 'function', insertText: 'bitushr(' },

  // Keywords & operators
  { label: 'true',       type: 'bool',    kind: 'keyword', insertText: 'true' },
  { label: 'false',      type: 'bool',    kind: 'keyword', insertText: 'false' },
  { label: 'nil',        type: 'nil',     kind: 'keyword', insertText: 'nil' },
  { label: 'in',         type: 'operator', kind: 'keyword', insertText: 'in ' },
  { label: 'not',        type: 'operator', kind: 'keyword', insertText: 'not ' },
  { label: 'and',        type: 'operator', kind: 'keyword', insertText: 'and ' },
  { label: 'or',         type: 'operator', kind: 'keyword', insertText: 'or ' },
  { label: 'matches',    type: '(str, pattern) bool', kind: 'keyword', insertText: 'matches ' },
  { label: 'contains',   type: '(str, substr) bool',  kind: 'keyword', insertText: 'contains ' },
  { label: 'startsWith', type: '(str, prefix) bool',  kind: 'keyword', insertText: 'startsWith ' },
  { label: 'endsWith',   type: '(str, suffix) bool',  kind: 'keyword', insertText: 'endsWith ' },
  { label: 'let',        type: 'declaration', kind: 'keyword', insertText: 'let ' },
]

/**
 * Given the text before the cursor and the env tree,
 * return completions for the current context.
 *
 * E.g. "http.Req.Me" → fields/methods of Req matching "Me"
 *      "http.Req."   → all fields/methods of Req
 *      "ht"          → top-level names + builtins matching "ht"
 *      ""            → all top-level names + builtins
 *
 * Also returns `replaceLen` — how many characters before the cursor
 * should be replaced by the chosen completion.
 */
export function getExprCompletions(
  textBeforeCursor: string,
  env: ExprEnvNode[],
): { items: ExprCompletion[]; replaceLen: number } {
  // Match a dotted identifier chain, possibly with a partial tail:
  //   "http.Req.Meth"  → path=["http","Req"], typed="Meth"
  //   "http.Req."      → path=["http","Req"], typed=""
  //   "ht"             → path=[], typed="ht"
  //   ""               → path=[], typed=""
  const chainMatch = textBeforeCursor.match(/([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\.([a-zA-Z_]\w*)?$/s)

  if (chainMatch) {
    const path = chainMatch[1].split('.')
    const typed = (chainMatch[2] ?? '').toLowerCase()
    const replaceLen = chainMatch[2]?.length ?? 0

    // Walk the env tree along the path
    let nodes = env
    for (const part of path) {
      const found = nodes.find(n => n.name === part)
      if (!found?.children?.length) return { items: [], replaceLen: 0 }
      nodes = found.children
    }

    const filtered = nodes.filter(n => !typed || n.name.toLowerCase().includes(typed))
    return {
      items: filtered.map(node => ({
        label: node.name,
        type: node.type,
        kind: node.kind,
        insertText: node.kind === 'method' ? node.name + '(' : node.name,
      })),
      replaceLen,
    }
  }

  // No dot — suggest top-level env names + builtins
  const wordMatch = textBeforeCursor.match(/([a-zA-Z_]\w*)$/s)
  const typed = wordMatch?.[1]?.toLowerCase() ?? ''
  const replaceLen = wordMatch?.[1]?.length ?? 0

  const envItems: ExprCompletion[] = env
    .filter(n => !typed || n.name.toLowerCase().includes(typed))
    .map(node => ({
      label: node.name,
      type: node.type,
      kind: node.kind,
      insertText: node.name,
    }))

  const builtinItems: ExprCompletion[] = BUILTINS
    .filter(b => !typed || b.label.toLowerCase().includes(typed))
    .map(b => ({
      label: b.label,
      type: b.type,
      kind: b.kind,
      insertText: b.insertText,
    }))

  return {
    items: [...envItems, ...builtinItems],
    replaceLen,
  }
}

/**
 * Collect all expr env data from schema definitions.
 * Returns a map from kind → field name → ExprEnvNode[].
 */
export function collectExprEnvs(
  definitions: Record<string, any> | undefined,
): Map<string, Map<string, ExprEnvNode[]>> {
  const result = new Map<string, Map<string, ExprEnvNode[]>>()
  if (!definitions) return result

  for (const [kind, def] of Object.entries(definitions)) {
    const props = def.properties as Record<string, any> | undefined
    if (!props) continue
    for (const [field, schema] of Object.entries(props)) {
      if (schema?.['x-expr'] && schema?.['x-expr-env']) {
        if (!result.has(kind)) result.set(kind, new Map())
        result.get(kind)!.set(field, schema['x-expr-env'] as ExprEnvNode[])
      }
    }
  }
  return result
}
