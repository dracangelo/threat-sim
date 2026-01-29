import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const threat = await db.threat.findUnique({
      where: { id },
    })

    if (!threat) {
      return NextResponse.json(
        { error: 'Threat not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(threat)
  } catch (error) {
    console.error('Error fetching threat:', error)
    return NextResponse.json(
      { error: 'Failed to fetch threat' },
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

    const threat = await db.threat.update({
      where: { id },
      data: {
        ...body,
        updatedAt: new Date(),
      },
    })

    return NextResponse.json(threat)
  } catch (error) {
    console.error('Error updating threat:', error)
    return NextResponse.json(
      { error: 'Failed to update threat' },
      { status: 500 }
    )
  }
}
