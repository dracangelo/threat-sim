import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const threatId = searchParams.get('threatId')
    const type = searchParams.get('type')
    const isActive = searchParams.get('isActive')
    const search = searchParams.get('search')

    const where: any = {}
    if (threatId) where.threatId = threatId
    if (type) where.type = type
    if (isActive !== null) where.isActive = isActive === 'true'

    if (search) {
      where.OR = [
        { value: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
      ]
    }

    const iocs = await db.iOC.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      include: {
        threat: {
          select: {
            id: true,
            title: true,
            severity: true,
            status: true,
          },
        },
      },
    })

    return NextResponse.json(iocs)
  } catch (error) {
    console.error('Error fetching IOCs:', error)
    return NextResponse.json(
      { error: 'Failed to fetch IOCs' },
      { status: 500 }
    )
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()

    const ioc = await db.iOC.create({
      data: {
        threatId: body.threatId,
        type: body.type,
        value: body.value,
        description: body.description,
        confidence: body.confidence,
        source: body.source,
        firstSeen: body.firstSeen,
        lastSeen: body.lastSeen,
        isActive: body.isActive !== undefined ? body.isActive : true,
      },
    })

    return NextResponse.json(ioc, { status: 201 })
  } catch (error) {
    console.error('Error creating IOC:', error)
    return NextResponse.json(
      { error: 'Failed to create IOC' },
      { status: 500 }
    )
  }
}
