import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const isApt = searchParams.get('isApt')
    const isActive = searchParams.get('isActive')
    const chainType = searchParams.get('chainType')

    const whereClause: any = {}

    if (isApt !== null && isApt !== undefined) {
      whereClause.isApt = isApt === 'true'
    }

    if (isActive !== null && isActive !== undefined) {
      whereClause.isActive = isActive === 'true'
    }

    if (chainType) {
      whereClause.chainType = chainType
    }

    const chains = await db.correlationChain.findMany({
      where: whereClause,
      include: {
        threats: {
          orderBy: {
            chainOrder: 'asc',
          },
          select: {
            id: true,
            title: true,
            severity: true,
            status: true,
            type: true,
            timestamp: true,
            chainOrder: true,
          },
        },
      },
      orderBy: {
        startTime: 'desc',
      },
    })

    // Enrich with threat counts
    const chainsWithStats = await Promise.all(
      chains.map(async (chain) => {
        const threatCount = await db.threat.count({
          where: {
            correlationChainId: chain.id,
          },
        })

        const criticalCount = await db.threat.count({
          where: {
            correlationChainId: chain.id,
            severity: 'CRITICAL',
          },
        })

        return {
          ...chain,
          threatCount,
          criticalCount,
        }
      })
    )

    return NextResponse.json(chainsWithStats)
  } catch (error) {
    console.error('Error fetching correlation chains:', error)
    return NextResponse.json(
      { error: 'Failed to fetch correlation chains' },
      { status: 500 }
    )
  }
}
