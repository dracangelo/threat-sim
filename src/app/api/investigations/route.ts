import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const threatId = searchParams.get('threatId')
    const status = searchParams.get('status')
    const assignedTo = searchParams.get('assignedTo')

    const where: any = {}
    if (threatId) where.threatId = threatId
    if (status) where.status = status
    if (assignedTo) where.assignedTo = { contains: assignedTo, mode: 'insensitive' }

    const investigations = await db.investigation.findMany({
      where,
      orderBy: { startTime: 'desc' },
      include: {
        threat: {
          select: {
            id: true,
            title: true,
            severity: true,
            type: true,
          },
        },
      },
    })

    return NextResponse.json(investigations)
  } catch (error) {
    console.error('Error fetching investigations:', error)
    return NextResponse.json(
      { error: 'Failed to fetch investigations' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()

    const investigation = await db.investigation.create({
      data: {
        threatId: body.threatId,
        title: body.title,
        description: body.description,
        status: body.status || 'OPEN',
        assignedTo: body.assignedTo,
        priority: body.priority || 'MEDIUM',
        endTime: body.endTime,
        findings: body.findings,
        actions: body.actions,
      },
    })

    return NextResponse.json(investigation, { status: 201 })
  } catch (error) {
    console.error('Error creating investigation:', error)
    return NextResponse.json(
      { error: 'Failed to create investigation' },
      { status: 500 }
    )
  }
}
