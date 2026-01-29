import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params

    const report = await db.report.findUnique({
      where: { id },
      include: {
        createdByUser: {
          select: {
            id: true,
            displayName: true,
            email: true,
            role: true,
          },
        },
        assignedToUser: {
          select: {
            id: true,
            displayName: true,
            email: true,
            role: true,
          },
        },
      },
    })

    if (!report) {
      return NextResponse.json(
        { error: 'Report not found' },
        { status: 404 }
      )
    }

    // Fetch related threats if threatIds exist
    let relatedThreats = []
    if (report.threatIds) {
      const threatIdList = report.threatIds.split(',')
      relatedThreats = await db.threat.findMany({
        where: {
          id: { in: threatIdList },
        },
        select: {
          id: true,
          title: true,
          severity: true,
          status: true,
          type: true,
          timestamp: true,
        },
      })
    }

    return NextResponse.json({
      ...report,
      relatedThreats,
    })
  } catch (error) {
    console.error('Error fetching report:', error)
    return NextResponse.json(
      { error: 'Failed to fetch report' },
      { status: 500 }
    )
  }
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const body = await request.json()

    const report = await db.report.update({
      where: { id },
      data: body,
    })

    return NextResponse.json(report)
  } catch (error) {
    console.error('Error updating report:', error)
    return NextResponse.json(
      { error: 'Failed to update report' },
      { status: 500 }
    )
  }
}
