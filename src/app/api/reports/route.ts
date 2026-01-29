import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const type = searchParams.get('type')
    const status = searchParams.get('status')
    const severity = searchParams.get('severity')

    const whereClause: any = {}

    if (type) {
      whereClause.type = type
    }

    if (status) {
      whereClause.status = status
    }

    if (severity) {
      whereClause.severity = severity
    }

    const reports = await db.report.findMany({
      where: whereClause,
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
      orderBy: {
        createdAt: 'desc',
      },
    })

    return NextResponse.json(reports)
  } catch (error) {
    console.error('Error fetching reports:', error)
    return NextResponse.json(
      { error: 'Failed to fetch reports' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const {
      title,
      type,
      description,
      severity,
      createdBy,
      assignedTo,
      threatIds,
      executiveSummary,
      keyFindings,
      recommendations,
    } = body

    // Generate report number
    const year = new Date().getFullYear()
    const month = String(new Date().getMonth() + 1).padStart(2, '0')
    const day = String(new Date().getDate()).padStart(2, '0')
    const reportNumber = `RPT-${year}${month}${day}-${Math.floor(Math.random() * 1000).toString().padStart(3, '0')}`

    const report = await db.report.create({
      data: {
        reportNumber,
        title,
        type,
        description,
        severity,
        status: 'DRAFT',
        createdBy,
        assignedTo,
        startDate: new Date(),
        threatIds: threatIds ? threatIds.join(',') : null,
        executiveSummary,
        keyFindings,
        recommendations,
      },
    })

    return NextResponse.json(report, { status: 201 })
  } catch (error) {
    console.error('Error creating report:', error)
    return NextResponse.json(
      { error: 'Failed to create report' },
      { status: 500 }
    )
  }
}
