// JSON Schema types and utilities for config GUI editor

export interface ExprEnvNode {
  name: string
  type: string
  kind: 'field' | 'method'
  children?: ExprEnvNode[]
}

export interface JsonSchema {
  $schema?: string
  type?: string
  properties?: Record<string, JsonSchema>
  required?: string[]
  additionalProperties?: JsonSchema | boolean
  allOf?: JsonSchema[]
  anyOf?: JsonSchema[]
  items?: JsonSchema
  prefixItems?: JsonSchema[]
  description?: string
  default?: unknown
  pattern?: string
  errorMessage?: string
  const?: string
  enum?: string[]
  if?: JsonSchema
  then?: JsonSchema
  'x-order'?: string[]
  'x-expr'?: boolean
  'x-expr-env'?: ExprEnvNode[]
}

export interface KindSchema {
  properties: Record<string, JsonSchema>
  required: string[]
  description: string
  additionalProperties?: JsonSchema | boolean
  order?: string[]
}

export type FieldType =
  | 'string' | 'integer' | 'boolean'
  | 'duration' | 'url' | 'hostname' | 'regexp'
  | 'ptr' | 'object' | 'array' | 'expr'

const DURATION_PATTERN = /^\^-\?/  // duration pattern starts with ^-?

/** Extract per-kind schemas from the top-level definitions (populated via $ref) */
export function parseKindSchemas(schema: JsonSchema): Map<string, KindSchema> {
  const map = new Map<string, KindSchema>()
  const defs = (schema as any).definitions as Record<string, JsonSchema> | undefined
  if (!defs) return map

  for (const [kind, def] of Object.entries(defs)) {
    map.set(kind, {
      properties: def.properties ?? {},
      required: def.required ?? [],
      description: def.description ?? '',
      additionalProperties: def.additionalProperties,
      order: def['x-order'],
    })
  }
  return map
}

/** Get all registered kind names */
export function allKindNames(kindSchemas: Map<string, KindSchema>): string[] {
  return Array.from(kindSchemas.keys()).sort()
}

/** Classify a JSON Schema field into our field types */
export function classifyField(schema: JsonSchema): FieldType {
  // ptr: anyOf with (ptr) string + object variant
  if (schema.anyOf) {
    const hasPtr = schema.anyOf.some(s =>
      s.type === 'string' && s.description?.startsWith('(ptr)')
    )
    if (hasPtr) return 'ptr'
  }

  // expr: string with x-expr flag
  if (schema['x-expr']) return 'expr'

  // duration: string with duration-like pattern
  if (schema.type === 'string' && schema.pattern && DURATION_PATTERN.test(schema.pattern)) {
    return 'duration'
  }

  // url: string with url-like pattern containing scheme
  if (schema.type === 'string' && schema.errorMessage?.includes('URL')) {
    return 'url'
  }

  // hostname
  if (schema.type === 'string' && schema.errorMessage?.includes('Hostname')) {
    return 'hostname'
  }

  // regexp
  if (schema.type === 'string' && schema.errorMessage?.includes('Regexp')) {
    return 'regexp'
  }

  if (schema.type === 'integer') return 'integer'
  if (schema.type === 'boolean') return 'boolean'
  if (schema.type === 'array') return 'array'
  if (schema.type === 'object') return 'object'
  return 'string'
}

/** Extract ptr field info from its anyOf schema */
export function parsePtrSchema(schema: JsonSchema): {
  allowedKinds: string[]
  isNullable: boolean
  inlineAllOf: JsonSchema[]
} {
  const allowedKinds: string[] = []
  let isNullable = false
  let inlineAllOf: JsonSchema[] = []

  for (const variant of schema.anyOf ?? []) {
    if (variant.type === 'null') {
      isNullable = true
    } else if (variant.type === 'object') {
      // Extract allowed kinds from kind.enum
      const kindEnum = variant.properties?.kind?.enum
      if (kindEnum) allowedKinds.push(...kindEnum)
      if (variant.allOf) inlineAllOf = variant.allOf
    }
  }

  return { allowedKinds, isNullable, inlineAllOf }
}

/** Get the inline schema for a specific kind from the ptr's allOf */
export function getInlineKindSchema(inlineAllOf: JsonSchema[], kind: string): KindSchema | null {
  for (const item of inlineAllOf) {
    if (item.if?.properties?.kind?.const === kind && item.then) {
      return {
        properties: item.then.properties ?? {},
        required: item.then.required ?? [],
        description: item.then.description ?? '',
        order: item.then['x-order'],
      }
    }
  }
  return null
}

/** Get default value for a field type */
export function defaultForType(schema: JsonSchema, fieldType: FieldType): unknown {
  if (schema.default !== undefined) return schema.default
  switch (fieldType) {
    case 'string': case 'duration': case 'url': case 'hostname': case 'regexp': case 'expr':
      return ''
    case 'integer': return 0
    case 'boolean': return false
    case 'array': return []
    case 'object': return {}
    case 'ptr': return ''
    default: return ''
  }
}

/** Filter service names that are compatible with a ptr field's allowed kinds */
export function compatibleServices(
  allServices: Record<string, { kind: string }>,
  allowedKinds: string[],
): string[] {
  if (allowedKinds.length === 0) {
    return Object.keys(allServices).sort()
  }
  const kindSet = new Set(allowedKinds)
  return Object.keys(allServices)
    .filter(name => kindSet.has(allServices[name].kind))
    .sort()
}
