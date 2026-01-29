import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams

    // Basic filters
    const severity = searchParams.get('severity')
    const type = searchParams.get('type')
    const status = searchParams.get('status')
    const isAnomaly = searchParams.get('isAnomaly')

    // Date range filters
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    const timeRange = searchParams.get('timeRange') // '24h', '7d', '30d', '90d'

    // Text search
    const search = searchParams.get('search')

    // Additional filters
    const assignedTo = searchParams.get('assignedTo')
    const detectionMethod = searchParams.get('detectionMethod')
    const sourceSystem = searchParams.get('sourceSystem')
    const hasIncident = searchParams.get('hasIncident')
    // Temporarily disabled correlationChainId and isApt filters
    // const correlationChainId = searchParams.get('correlationChainId')
    // const isApt = searchParams.get('isApt')

    // Pagination
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '20')
    const offset = (page - 1) * limit

    // Sorting
    const sortBy = searchParams.get('sortBy') || 'timestamp'
    const sortOrder = searchParams.get('sortOrder') || 'desc'

    const where: any = {}

    // Apply basic filters
    if (severity) where.severity = severity
    if (type) where.type = type
    if (status) where.status = status
    if (isAnomaly !== null) where.isAnomaly = isAnomaly === 'true'

    // Apply date range filters
    if (timeRange) {
      const now = new Date()
      const startTime = new Date()

      switch (timeRange) {
        case '24h':
          startTime.setHours(now.getHours() - 24)
          break
        case '7d':
          startTime.setDate(now.getDate() - 7)
          break
        case '30d':
          startTime.setDate(now.getDate() - 30)
          break
        case '90d':
          startTime.setDate(now.getDate() - 90)
          break
      }

      where.timestamp = {
        gte: startTime,
      }
    } else if (startDate || endDate) {
      where.timestamp = {}
      if (startDate) where.timestamp.gte = new Date(startDate)
      if (endDate) where.timestamp.lte = new Date(endDate)
    }

    // Apply text search
    if (search) {
      const searchLower = search.toLowerCase()
      where.OR = [
        { title: { contains: searchLower, mode: 'insensitive' } },
        { description: { contains: searchLower, mode: 'insensitive' } },
        { sourceIp: { contains: searchLower, mode: 'insensitive' } },
        { destinationIp: { contains: searchLower, mode: 'insensitive' } },
        { affectedHosts: { contains: searchLower, mode: 'insensitive' } },
        { affectedUsers: { contains: searchLower, mode: 'insensitive' } },
        { incidentId: { contains: searchLower, mode: 'insensitive' } },
      ]
    }

    // Apply additional filters
    if (assignedTo) where.assignedTo = { contains: assignedTo, mode: 'insensitive' }
    // Temporarily disable APT and correlation chain filters due to Prisma relation issues
    // if (correlationChainId) where.correlationChainId = correlationChainId
    // if (isApt !== null && isApt !== undefined) {
    //   // Filter by APT correlation chains
    //   const aptChains = await db.correlationChain.findMany({
    //     where: { isApt: isApt === 'true' },
    //     select: { id: true },
    //   })
    //   where.correlationChainId = { in: aptChains.map(c => c.id) }
    // }
    if (detectionMethod) where.detectionMethod = detectionMethod
    if (sourceSystem) where.sourceSystem = sourceSystem
    if (hasIncident) {
      if (hasIncident === 'true') {
        where.incidentId = { not: null }
      } else {
        where.incidentId = null
      }
    }

    // Get total count
    const total = await db.threat.count({ where })

    // Get threats with pagination and sorting
    const threats = await db.threat.findMany({
      where,
      orderBy: { timestamp: 'desc' as const },
      take: limit,
      skip: offset,
    })

    return NextResponse.json({
      threats,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    })
  } catch (error) {
    console.error('Error fetching threats:', error)
    return NextResponse.json(
      { error: 'Failed to fetch threats', details: error.message },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()

    const threat = await db.threat.create({
      data: {
        title: body.title,
        description: body.description,
        severity: body.severity || 'MEDIUM',
        type: body.type,
        status: body.status || 'DETECTED',
        sourceIp: body.sourceIp,
        destinationIp: body.destinationIp,
        sourcePort: body.sourcePort,
        destinationPort: body.destinationPort,
        protocol: body.protocol,
        isAnomaly: body.isAnomaly || false,
        anomalyScore: body.anomalyScore,
        confidence: body.confidence,
        mitreTactics: body.mitreTactics,
        mitreTechniques: body.mitreTechniques,
        evidence: body.evidence,
        assignedTo: body.assignedTo,
        resolvedAt: body.resolvedAt,
        resolvedBy: body.resolvedBy,
        incidentId: body.incidentId,
        detectionMethod: body.detectionMethod || 'MANUAL',
        sourceSystem: body.sourceSystem || 'MANUAL',
        firstSeen: body.firstSeen || new Date(),
        lastSeen: body.lastSeen,
        affectedHosts: body.affectedHosts,
        affectedUsers: body.affectedUsers,
        remediation: body.remediation,
        notes: body.notes,
        tags: body.tags,
        priority: body.priority || 0,
      },
    })

    return NextResponse.json(threat, { status: 201 })
  } catch (error) {
    console.error('Error creating threat:', error)
    return NextResponse.json(
      { error: 'Failed to create threat', details: error.message },
      { status: 500 }
    )
  }
}

