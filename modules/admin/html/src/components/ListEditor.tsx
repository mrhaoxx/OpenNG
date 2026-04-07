import { useState } from 'react'
import { Plus, Trash2, GripVertical } from 'lucide-react'
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core'
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import type { JsonSchema, KindSchema } from '@/lib/schema'
import { classifyField, defaultForType } from '@/lib/schema'
import { AssertForm } from './AssertForm'
import { PtrField } from './PtrField'
import { MapEditor } from './MapEditor'

export interface ListEditorProps {
  value: any[]
  itemSchema: JsonSchema
  kindSchemas: Map<string, KindSchema>
  allServices: Record<string, { kind: string }>
  onChange: (v: any[]) => void
  path: string
  depth: number
}

interface SortableItemProps {
  id: string
  index: number
  children: React.ReactNode
  onRemove: () => void
}

function SortableItem({ id, index, children, onRemove }: SortableItemProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id })

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  }

  return (
    <div ref={setNodeRef} style={style} className="flex items-start gap-1">
      <button
        type="button"
        className="p-1 text-neutral-600 hover:text-neutral-400 cursor-grab active:cursor-grabbing shrink-0 mt-0.5"
        {...attributes}
        {...listeners}
      >
        <GripVertical className="size-3.5" />
      </button>
      <span className="text-xs text-neutral-500 pt-1.5 w-5 shrink-0 text-right tabular-nums">
        {index}
      </span>
      <div className="flex-1 min-w-0">
        {children}
      </div>
      <button
        type="button"
        onClick={onRemove}
        className="p-1 text-neutral-500 hover:text-red-400 shrink-0 mt-0.5"
        title="Remove item"
      >
        <Trash2 className="size-4" />
      </button>
    </div>
  )
}

export function ListEditor({
  value,
  itemSchema,
  kindSchemas,
  allServices,
  onChange,
  path,
  depth,
}: ListEditorProps) {
  const itemType = classifyField(itemSchema)
  // Stable IDs for dnd-kit (index-based IDs shift on reorder, so use a counter)
  const [idCounter, setIdCounter] = useState(() => value.length)
  const [itemIds, setItemIds] = useState<string[]>(() =>
    value.map((_, i) => `item-${i}`)
  )

  // Keep IDs in sync when value length changes externally
  if (itemIds.length !== value.length) {
    const newIds = value.map((_, i) => itemIds[i] ?? `item-${idCounter + i}`)
    setItemIds(newIds)
    setIdCounter(idCounter + Math.max(0, value.length - itemIds.length))
  }

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  )

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event
    if (!over || active.id === over.id) return

    const oldIndex = itemIds.indexOf(String(active.id))
    const newIndex = itemIds.indexOf(String(over.id))
    if (oldIndex === -1 || newIndex === -1) return

    const newValue = [...value]
    const newIds = [...itemIds]
    const [movedValue] = newValue.splice(oldIndex, 1)
    const [movedId] = newIds.splice(oldIndex, 1)
    newValue.splice(newIndex, 0, movedValue)
    newIds.splice(newIndex, 0, movedId)

    setItemIds(newIds)
    onChange(newValue)
  }

  const updateItem = (index: number, val: any) => {
    const next = [...value]
    next[index] = val
    onChange(next)
  }

  const removeItem = (index: number) => {
    const newIds = [...itemIds]
    newIds.splice(index, 1)
    setItemIds(newIds)
    onChange(value.filter((_, i) => i !== index))
  }

  const addItem = () => {
    const newId = `item-${idCounter}`
    setIdCounter(idCounter + 1)
    setItemIds([...itemIds, newId])
    onChange([...value, defaultForType(itemSchema, itemType)])
  }

  const renderItem = (item: any, index: number) => {
    if (itemType === 'ptr') {
      return (
        <PtrField
          value={item}
          schema={itemSchema}
          kindSchemas={kindSchemas}
          allServices={allServices}
          onChange={(v) => updateItem(index, v)}
          path={`${path}[${index}]`}
          depth={depth + 1}
        />
      )
    }

    if (itemType === 'array' && itemSchema.items) {
      return (
        <ListEditor
          value={Array.isArray(item) ? item : []}
          itemSchema={itemSchema.items}
          kindSchemas={kindSchemas}
          allServices={allServices}
          onChange={(v) => updateItem(index, v)}
          path={`${path}[${index}]`}
          depth={depth + 1}
        />
      )
    }

    if (itemType === 'object' && itemSchema.properties) {
      return (
        <div className="border border-neutral-700 rounded-md p-3 bg-neutral-800/50">
          <AssertForm
            schema={itemSchema.properties}
            required={itemSchema.required ?? []}
            value={typeof item === 'object' && item !== null ? item : {}}
            onChange={(v) => updateItem(index, v)}
            kindSchemas={kindSchemas}
            allServices={allServices}
            path={`${path}[${index}]`}
            depth={depth + 1}
          />
        </div>
      )
    }

    if (itemType === 'object' && itemSchema.additionalProperties && typeof itemSchema.additionalProperties === 'object') {
      return (
        <MapEditor
          value={typeof item === 'object' && item !== null ? item : {}}
          valueSchema={itemSchema.additionalProperties}
          kindSchemas={kindSchemas}
          allServices={allServices}
          onChange={(v) => updateItem(index, v)}
          path={`${path}[${index}]`}
          depth={depth + 1}
        />
      )
    }

    if (itemType === 'boolean') {
      return (
        <input
          type="checkbox"
          checked={!!item}
          onChange={(e) => updateItem(index, e.target.checked)}
          className="h-4 w-4 rounded border-neutral-700 bg-neutral-800 accent-blue-500"
        />
      )
    }

    if (itemType === 'integer') {
      return (
        <input
          type="number"
          value={item ?? 0}
          onChange={(e) => updateItem(index, parseInt(e.target.value) || 0)}
          className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground w-full"
        />
      )
    }

    return (
      <input
        type="text"
        value={typeof item === 'object' ? JSON.stringify(item) : (item ?? '')}
        onChange={(e) => updateItem(index, e.target.value)}
        className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-sm text-foreground w-full"
        placeholder={itemType === 'duration' ? 'e.g. 30s, 5m' : undefined}
      />
    )
  }

  return (
    <div className="space-y-2">
      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
        <SortableContext items={itemIds} strategy={verticalListSortingStrategy}>
          {value.map((item, index) => (
            <SortableItem
              key={itemIds[index]}
              id={itemIds[index]}
              index={index}
              onRemove={() => removeItem(index)}
            >
              {renderItem(item, index)}
            </SortableItem>
          ))}
        </SortableContext>
      </DndContext>
      <button
        type="button"
        onClick={addItem}
        className="flex items-center gap-1 text-xs text-neutral-400 hover:text-neutral-200 transition-colors"
      >
        <Plus className="size-3.5" />
        Add item
      </button>
    </div>
  )
}
