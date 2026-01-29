import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const body = await request.json()

    // Destructure known fields from body to avoid polluting updateData
    const {
      action,
      assignedTo,
      assignedToId,
      assignedBy,
      status,
      resolvedBy,
      updatedBy,
      notes,
      addedBy,
      tags,
      remediation,
      remediatedBy,
      containedBy,
      escalatedBy,
      markedBy,
      closedBy
    } = body

    // Initialize updateData only with fields we intend to update on the Threat model
    let updateData: any = {}
    let timelineDescription = ''
    let timelineEventType = ''
    let timelineUserId = ''

    switch (action) {
      case 'assign':
        // Support both old string assignment and new user ID assignment
        if (assignedToId) {
          updateData.assignedToId = assignedToId
          // Fetch user display name
          const user = await db.user.findUnique({
            where: { id: assignedToId },
            select: { displayName: true },
          })
          updateData.assignedTo = user?.displayName || assignedToId
        } else {
          updateData.assignedTo = assignedTo
        }
        updateData.status = 'INVESTIGATING'

        timelineEventType = 'ASSIGNMENT'
        timelineDescription = `Threat assigned to ${updateData.assignedTo}`
        timelineUserId = assignedBy || assignedToId
        break

      case 'updateStatus':
        updateData.status = status
        if (status === 'RESOLVED' || status === 'CLOSED') {
          updateData.resolvedAt = new Date()
          updateData.resolvedBy = resolvedBy
        }

        timelineEventType = 'STATUS_CHANGE'
        timelineDescription = `Status changed to ${status}`
        timelineUserId = updatedBy
        break

      case 'addNote':
        // For notes, we might want to update a 'notes' field on Threat or just add to timeline
        // If Threat model has 'notes', update it. But usually notes are just timeline events.
        // The original code updated 'notes' field.
        updateData.notes = notes

        timelineEventType = 'NOTE_ADDED'
        timelineDescription = notes
        timelineUserId = addedBy
        break

      case 'updateTags':
        updateData.tags = tags
        break

      case 'remediate':
        updateData.status = 'CONTAINED'
        updateData.remediation = remediation

        timelineEventType = 'REMEDIATION'
        timelineDescription = `Remediation actions: ${remediation}`
        timelineUserId = remediatedBy
        break

      case 'contain':
        updateData.status = 'CONTAINED'

        timelineEventType = 'CONTAINMENT'
        timelineDescription = 'Threat containment actions executed'
        timelineUserId = containedBy
        break

      case 'resolve':
        updateData.status = 'RESOLVED'
        updateData.resolvedAt = new Date()
        updateData.resolvedBy = resolvedBy

        timelineEventType = 'RESOLUTION'
        timelineDescription = 'Threat resolved'
        timelineUserId = resolvedBy
        break

      case 'escalate':
        updateData.status = 'ESCALATED'

        timelineEventType = 'ESCALATION'
        timelineDescription = 'Threat escalated to higher level'
        timelineUserId = escalatedBy
        break

      case 'falsePositive':
        updateData.status = 'FALSE_POSITIVE'

        timelineEventType = 'FALSE_POSITIVE'
        timelineDescription = 'Marked as false positive'
        timelineUserId = markedBy
        break

      case 'close':
        updateData.status = 'CLOSED'
        updateData.resolvedAt = new Date()
        updateData.resolvedBy = closedBy

        timelineEventType = 'CLOSURE'
        timelineDescription = 'Threat closed'
        timelineUserId = closedBy
        break

      default:
        return NextResponse.json(
          { error: 'Invalid action' },
          { status: 400 }
        )
    }

    // Perform database operations in transaction
    const result = await db.$transaction(async (tx) => {
      // 1. Update Threat
      let threat
      if (Object.keys(updateData).length > 0) {
        threat = await tx.threat.update({
          where: { id },
          data: {
            ...updateData,
            updatedAt: new Date(),
          },
        })
      } else {
        threat = await tx.threat.findUnique({ where: { id } })
      }

      // 2. Create Timeline Event if applicable
      if (timelineEventType) {
        await tx.timelineEvent.create({
          data: {
            threatId: id,
            eventType: timelineEventType,
            eventTime: new Date(),
            description: timelineDescription,
            userId: timelineUserId || 'system',
            source: 'MANUAL',
          },
        })
      }

      return threat
    })

    return NextResponse.json(result)
  } catch (error: any) {
    console.error('Error performing threat action:', error)
    return NextResponse.json(
      { error: 'Failed to perform threat action', details: error.message },
      { status: 500 }
    )
  }
}
