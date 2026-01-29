import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { Severity, ThreatType, ThreatStatus } from '@prisma/client';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const severity = searchParams.get('severity');
    const type = searchParams.get('type');
    const status = searchParams.get('status');
    const isAnomaly = searchParams.get('isAnomaly');
    const search = searchParams.get('search');

    let whereClause: any = {};

    if (severity && severity !== 'all') {
      whereClause.severity = severity.toUpperCase();
    }

    if (type && type !== 'all') {
      const typeMap: Record<string, ThreatType> = {
        'malware': ThreatType.MALWARE,
        'phishing': ThreatType.PHISHING,
        'ddos': ThreatType.DDOS,
        'intrusion': ThreatType.INTRUSION,
        'data_exfiltration': ThreatType.DATA_EXFILTRATION,
        'unauthorized_access': ThreatType.UNAUTHORIZED_ACCESS,
        'suspicious_behavior': ThreatType.SUSPICIOUS_BEHAVIOR,
        'anomaly': ThreatType.ANOMALY,
      };
      if (typeMap[type]) {
        whereClause.type = typeMap[type];
      }
    }

    if (status && status !== 'all') {
      const statusMap: Record<string, ThreatStatus> = {
        'detected': ThreatStatus.DETECTED,
        'investigating': ThreatStatus.INVESTIGATING,
        'contained': ThreatStatus.CONTAINED,
        'resolved': ThreatStatus.RESOLVED,
        'false_positive': ThreatStatus.FALSE_POSITIVE,
      };
      if (statusMap[status]) {
        whereClause.status = statusMap[status];
      }
    }

    if (isAnomaly === 'true') {
      whereClause.isAnomaly = true;
    } else if (isAnomaly === 'false') {
      whereClause.isAnomaly = false;
    }

    if (search) {
      whereClause.OR = [
        { description: { contains: search } },
        { sourceIp: { contains: search } },
        { destinationIp: { contains: search } },
        { title: { contains: search } },
      ];
    }

    const threats = await db.threat.findMany({
      where: whereClause,
      orderBy: {
        timestamp: 'desc',
      },
      take: 1000,
    });

    // Transform the data to match the frontend expectations
    const transformedEvents = threats.map((threat) => ({
      id: threat.id,
      eventType: threat.type.toLowerCase(),
      severity: threat.severity.toLowerCase(),
      sourceIP: threat.sourceIp || '',
      destIP: threat.destinationIp || null,
      timestamp: threat.timestamp,
      protocol: threat.protocol || 'unknown',
      port: threat.port || null,
      description: threat.description,
      status: threat.status.toLowerCase().replace('_', ' '),
      isAnomaly: threat.isAnomaly,
      anomalyScore: threat.anomalyScore,
      anomalyReason: threat.evidence || null,
      user: threat.assignedTo || null,
      hostname: null,
      filePath: null,
      hash: null,
      malwareFamily: threat.mitreTechniques || null,
      attackPattern: threat.mitreTactics || null,
    }));

    return NextResponse.json(transformedEvents);
  } catch (error) {
    console.error('Error fetching events:', error);
    return NextResponse.json({ error: 'Failed to fetch events' }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();

    const threat = await db.threat.create({
      data: {
        title: body.title || 'Untitled Threat',
        description: body.description || 'No description',
        severity: (body.severity || 'MEDIUM').toUpperCase(),
        type: (body.type || 'SUSPICIOUS_BEHAVIOR').toUpperCase(),
        status: (body.status || 'DETECTED').toUpperCase(),
        sourceIp: body.sourceIP || null,
        destinationIp: body.destIP || null,
        port: body.port || null,
        protocol: body.protocol || null,
        timestamp: body.timestamp ? new Date(body.timestamp) : undefined,
        isAnomaly: false,
        mitreTactics: body.attackPattern || null,
        mitreTechniques: body.malwareFamily || null,
        evidence: body.anomalyReason || null,
        assignedTo: body.user || null,
      },
    });

    return NextResponse.json(threat);
  } catch (error) {
    console.error('Error creating threat:', error);
    return NextResponse.json({ error: 'Failed to create threat' }, { status: 500 });
  }
}
