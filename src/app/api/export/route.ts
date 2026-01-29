import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const format = searchParams.get('format') || 'json'
    const threatIds = searchParams.get('threatIds')?.split(',')

    const where: any = {}
    if (threatIds && threatIds.length > 0) {
      where.id = { in: threatIds }
    }

    const threats = await db.threat.findMany({
      where,
      orderBy: { timestamp: 'desc' },
      include: {
        iocs: true,
        timelineEvents: {
          orderBy: { eventTime: 'asc' },
        },
      },
    })

    if (format === 'csv') {
      // Generate CSV format
      const headers = [
        'ID',
        'Title',
        'Description',
        'Severity',
        'Type',
        'Status',
        'Source IP',
        'Destination IP',
        'Source Port',
        'Destination Port',
        'Protocol',
        'Timestamp',
        'Is Anomaly',
        'Anomaly Score',
        'Confidence',
        'MITRE Tactics',
        'MITRE Techniques',
        'Assigned To',
        'Incident ID',
        'Detection Method',
        'Source System',
        'Affected Hosts',
        'Affected Users',
        'Created At',
      ]

      const rows = threats.map(threat => [
        threat.id,
        `"${threat.title.replace(/"/g, '""')}"`,
        `"${threat.description.replace(/"/g, '""')}"`,
        threat.severity,
        threat.type,
        threat.status,
        threat.sourceIp || '',
        threat.destinationIp || '',
        threat.sourcePort || '',
        threat.destinationPort || '',
        threat.protocol || '',
        threat.timestamp.toISOString(),
        threat.isAnomaly,
        threat.anomalyScore || '',
        threat.confidence || '',
        threat.mitreTactics || '',
        threat.mitreTechniques || '',
        threat.assignedTo || '',
        threat.incidentId || '',
        threat.detectionMethod,
        threat.sourceSystem,
        threat.affectedHosts || '',
        threat.affectedUsers || '',
        threat.createdAt.toISOString(),
      ])

      const csv = [headers.join(','), ...rows.map(row => row.join(','))].join('\n')

      return new NextResponse(csv, {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="threat-hunting-export-${new Date().toISOString()}.csv"`,
        },
      })
    }

    // Default JSON format
    const exportData = {
      exportedAt: new Date().toISOString(),
      totalThreats: threats.length,
      threats: threats.map(threat => ({
        ...threat,
        iocs: threat.iocs,
        timeline: threat.timelineEvents,
      })),
    }

    return new NextResponse(JSON.stringify(exportData, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="threat-hunting-export-${new Date().toISOString()}.json"`,
      },
    })
  } catch (error) {
    console.error('Error exporting data:', error)
    return NextResponse.json(
      { error: 'Failed to export data' },
      { status: 500 }
    )
  }
}
