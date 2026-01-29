import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const status = searchParams.get('status')
    const severity = searchParams.get('severity')
    const assignedTo = searchParams.get('assignedTo')

    const where: any = {}
    if (status) where.status = status
    if (severity) where.severity = severity
    if (assignedTo) where.assignedTo = { contains: assignedTo, mode: 'insensitive' }

    const incidents = await db.incident.findMany({
      where,
      orderBy: { reportedAt: 'desc' },
    })

    return NextResponse.json(incidents)
  } catch (error) {
    console.error('Error fetching incidents:', error)
    return NextResponse.json(
      { error: 'Failed to fetch incidents' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()

    const incident = await db.investigation.create({
      data: {
        incidentNumber: body.incidentNumber,
        title: body.title,
        description: body.description,
        severity: body.severity || 'MEDIUM',
        status: body.status || 'OPEN',
        assignedTo: body.assignedTo,
        reportedBy: body.reportedBy,
        resolvedAt: body.resolvedAt,
        resolution: body.resolution,
        rootCause: body.rootCause,
        lessons: body.lessons,
        relatedThreats: body.relatedThreats,
        confidence: body.confidence,
      },
    })

    return NextResponse.json(incident, { status: 201 })
  } catch (error) {
    console.error('Error creating incident:', error)
    return NextResponse.json(
      { error: 'Failed to create incident' },
      { status: 500 }
    )
  }
}
