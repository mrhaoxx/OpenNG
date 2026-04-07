export interface Widget {
  type: string
  props: Record<string, any>
  children?: Widget[]
}

export interface ColumnDef {
  field: string
  label: string
  type: string
  sortable?: boolean
  width?: string
  colorMap?: Record<string, string>
}
