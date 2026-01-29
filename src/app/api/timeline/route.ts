import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const threatId = searchParams.get('threatId')

    const where: any = {}
    if (threatId) where.threatId = threatId

    const events = await db.timelineEvent.findMany({
      where,
      orderBy: { eventTime: 'desc' },
    })

    return NextResponse.json(events)
  } catch (error) {
    console.error('Error fetching timeline events:', error)
    return NextResponse.json(
      { error: 'Failed to fetch timeline events' },
      { status: 500 }
    )
  }
}
