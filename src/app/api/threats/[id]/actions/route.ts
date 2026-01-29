import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const body = await request.json()

    const { action, ...data } = body

    let updateData: any = { ...data }

    switch (action) {
      case 'assign':
        // Support both old string assignment and new user ID assignment
        if (data.assignedToId) {
          updateData.assignedToId = data.assignedToId
          // Fetch user display name
          const user = await db.user.findUnique({
            where: { id: data.assignedToId },
            select: { displayName: true },
          })
          updateData.assignedTo = user?.displayName || data.assignedToId
        } else {
          updateData.assignedTo = data.assignedTo
        }
        updateData.status = 'INVESTIGATING'
        // Create timeline event
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'ASSIGNMENT',
            eventTime: new Date(),
            description: `Threat assigned to ${updateData.assignedTo}`,
            userId: data.assignedBy || data.assignedToId,
            source: 'MANUAL',
          },
        })
        break

      case 'updateStatus':
        updateData.status = data.status
        if (data.status === 'RESOLVED' || data.status === 'CLOSED') {
          updateData.resolvedAt = new Date()
          updateData.resolvedBy = data.resolvedBy
        }
        // Create timeline event
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'STATUS_CHANGE',
            eventTime: new Date(),
            description: `Status changed to ${data.status}`,
            userId: data.updatedBy,
            source: 'MANUAL',
          },
        })
        break

      case 'addNote':
        updateData.notes = data.notes
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'NOTE_ADDED',
            eventTime: new Date(),
            description: data.notes,
            userId: data.addedBy,
            source: 'MANUAL',
          },
        })
        break

      case 'updateTags':
        updateData.tags = data.tags
        break

      case 'remediate':
        updateData.status = 'CONTAINED'
        updateData.remediation = data.remediation
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'REMEDIATION',
            eventTime: new Date(),
            description: `Remediation actions: ${data.remediation}`,
            userId: data.remediatedBy,
            source: 'MANUAL',
          },
        })
        break

      case 'contain':
        updateData.status = 'CONTAINED'
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'CONTAINMENT',
            eventTime: new Date(),
            description: 'Threat containment actions executed',
            userId: data.containedBy,
            source: 'MANUAL',
          },
        })
        break

      case 'resolve':
        updateData.status = 'RESOLVED'
        updateData.resolvedAt = new Date()
        updateData.resolvedBy = data.resolvedBy
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'RESOLUTION',
            eventTime: new Date(),
            description: 'Threat resolved',
            userId: data.resolvedBy,
            source: 'MANUAL',
          },
        })
        break

      case 'escalate':
        updateData.status = 'ESCALATED'
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'ESCALATION',
            eventTime: new Date(),
            description: 'Threat escalated to higher level',
            userId: data.escalatedBy,
            source: 'MANUAL',
          },
        })
        break

      case 'falsePositive':
        updateData.status = 'FALSE_POSITIVE'
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'FALSE_POSITIVE',
            eventTime: new Date(),
            description: 'Marked as false positive',
            userId: data.markedBy,
            source: 'MANUAL',
          },
        })
        break

      case 'close':
        updateData.status = 'CLOSED'
        updateData.resolvedAt = new Date()
        updateData.resolvedBy = data.closedBy
        await db.timelineEvent.create({
          data: {
            threatId: id,
            eventType: 'CLOSURE',
            eventTime: new Date(),
            description: 'Threat closed',
            userId: data.closedBy,
            source: 'MANUAL',
          },
        })
        break

      default:
        return NextResponse.json(
          { error: 'Invalid action' },
          { status: 400 }
        )
    }

    const threat = await db.threat.update({
      where: { id },
      data: updateData,
    })

    return NextResponse.json(threat)
  } catch (error) {
    console.error('Error performing threat action:', error)
    return NextResponse.json(
      { error: 'Failed to perform threat action', details: error.message },
      { status: 500 }
    )
  }
}
