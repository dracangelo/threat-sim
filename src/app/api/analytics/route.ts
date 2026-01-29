import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const days = searchParams.get('days') ? parseInt(searchParams.get('days')!) : 30

    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)
    startDate.setHours(0, 0, 0, 0)

    const analyticsData = await db.analyticsData.findMany({
      where: {
        date: {
          gte: startDate,
        },
      },
      orderBy: { date: 'asc' },
    })

    // Current threats summary
    const currentThreats = await db.threat.groupBy({
      by: ['status', 'severity'],
      _count: true,
    })

    const totals = await db.threat.aggregate({
      _count: true,
      _avg: {
        confidence: true,
        anomalyScore: true,
      },
      where: {
        timestamp: {
          gte: startDate,
        },
      },
    })

    // Active investigations
    const activeInvestigations = await db.investigation.count({
      where: {
        status: 'OPEN',
      },
    })

    // Unique IOCs
    const uniqueIocs = await db.iOC.groupBy({
      by: ['type'],
      _count: {
        type: true,
      },
      where: {
        isActive: true,
      },
    })

    // Threat trends by type
    const threatTypes = await db.threat.groupBy({
      by: ['type'],
      _count: true,
      orderBy: {
        _count: {
          type: 'desc',
        },
      },
      where: {
        timestamp: {
          gte: startDate,
        },
      },
    })

    // Detection methods distribution
    const detectionMethods = await db.threat.groupBy({
      by: ['detectionMethod', 'sourceSystem'],
      _count: true,
    })

    // MTTR and MTTD from analytics
    const latestAnalytics = analyticsData[analyticsData.length - 1]
    const mttr = latestAnalytics?.mttr || 0
    const mttd = latestAnalytics?.mttd || 0

    // Calculate resolution rate
    const resolvedThreats = await db.threat.count({
      where: {
        status: { in: ['RESOLVED', 'FALSE_POSITIVE'] },
        timestamp: {
          gte: startDate,
        },
      },
    })

    const resolutionRate = totals._count > 0
      ? (resolvedThreats / totals._count) * 100
      : 0

    // Active incidents
    const activeIncidents = await db.incident.count({
      where: {
        status: 'OPEN',
      },
    })

    return NextResponse.json({
      timeline: analyticsData,
      summary: {
        totalThreats: totals._count,
        avgConfidence: totals._avg.confidence || 0,
        avgAnomalyScore: totals._avg.anomalyScore || 0,
        activeInvestigations,
        uniqueIocs: uniqueIocs.reduce((sum, group) => sum + group._count.type, 0),
        resolutionRate: Math.round(resolutionRate * 100) / 100,
        mttr: Math.round(mttr * 100) / 100,
        mttd: Math.round(mttd * 100) / 100,
        activeIncidents,
      },
      statusDistribution: currentThreats,
      threatTypeDistribution: threatTypes,
      detectionMethodDistribution: detectionMethods,
      iocDistribution: uniqueIocs,
    })
  } catch (error) {
    console.error('Error fetching analytics:', error)
    return NextResponse.json(
      { error: 'Failed to fetch analytics', details: error.message },
      { status: 500 }
    )
  }
}
