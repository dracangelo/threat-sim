import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import ZAI from 'z-ai-web-dev-sdk';

export async function POST(request: Request) {
  try {
    const threats = await db.threat.findMany({
      where: {
        timestamp: {
          gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // Last 7 days
        },
      },
      orderBy: {
        timestamp: 'desc',
      },
      take: 100,
    });

    if (threats.length === 0) {
      return NextResponse.json({ success: false, message: 'No threats to analyze' });
    }

    // Initialize ZAI
    const zai = await ZAI.create();

    const systemPrompt = `You are an expert security analyst specialized in threat hunting and anomaly detection.
Analyze security threats and identify suspicious patterns that may indicate:
- Unusual network traffic patterns
- Suspicious login attempts or authentication anomalies
- Lateral movement or privilege escalation attempts
- Data exfiltration indicators
- Known attack patterns or MITRE ATT&CK techniques
- Rare or abnormal threat combinations

For each threat that you flag as anomalous, provide:
1. Anomaly score (0-1, where 1 is highly anomalous)
2. Reason for flagging (specific indicators)
3. Recommended investigation steps

Respond in JSON format with an array of anomalies. Each anomaly should include:
- threatId: the ID of the threat
- isAnomaly: boolean (true if anomalous)
- anomalyScore: float between 0 and 1
- anomalyReason: string explanation

Example response format:
{
  "anomalies": [
    {
      "threatId": "threat_id_1",
      "isAnomaly": true,
      "anomalyScore": 0.85,
      "anomalyReason": "Unusual number of failed login attempts from external IP within short timeframe"
    }
  ]
}`;

    // Prepare threats data for analysis
    const threatsSummary = threats.map((threat) => ({
      id: threat.id,
      title: threat.title,
      type: threat.type,
      severity: threat.severity,
      sourceIp: threat.sourceIp,
      destinationIp: threat.destinationIp,
      timestamp: threat.timestamp.toISOString(),
      protocol: threat.protocol,
      port: threat.port,
      description: threat.description,
      assignedTo: threat.assignedTo,
      mitreTactics: threat.mitreTactics,
      mitreTechniques: threat.mitreTechniques,
    }));

    const userPrompt = `Analyze these ${threatsSummary.length} security threats for anomalies:
${JSON.stringify(threatsSummary, null, 2)}

Consider patterns like:
- Repeated failed access attempts from same source
- Unusual time-of-day activity
- Rare event types in context
- High-severity threats with low-frequency patterns
- Combinations of threats that suggest attack chains

Provide anomaly assessment for each threat.`;

    const completion = await zai.chat.completions.create({
      messages: [
        {
          role: 'assistant',
          content: systemPrompt,
        },
        {
          role: 'user',
          content: userPrompt,
        },
      ],
      thinking: { type: 'disabled' },
    });

    const responseContent = completion.choices[0]?.message?.content;

    if (!responseContent) {
      return NextResponse.json({ success: false, message: 'No response from AI' }, { status: 500 });
    }

    // Parse the JSON response
    let anomaliesData;
    try {
      // Try to extract JSON from the response
      const jsonMatch = responseContent.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        anomaliesData = JSON.parse(jsonMatch[0]);
      } else {
        anomaliesData = JSON.parse(responseContent);
      }
    } catch (parseError) {
      console.error('Failed to parse AI response:', parseError);
      console.error('Response content:', responseContent);

      // Fallback: use basic pattern detection
      anomaliesData = {
        anomalies: threats
          .filter((t) => t.severity === 'CRITICAL' || t.severity === 'HIGH')
          .map((t) => ({
            threatId: t.id,
            isAnomaly: true,
            anomalyScore: 0.7,
            anomalyReason: 'High severity threat flagged by baseline analysis',
          })),
      };
    }

    const anomalies = anomaliesData.anomalies || [];

    // Update database with anomaly results
    for (const anomaly of anomalies) {
      await db.threat.update({
        where: { id: anomaly.threatId },
        data: {
          isAnomaly: anomaly.isAnomaly,
          anomalyScore: anomaly.anomalyScore,
          evidence: anomaly.anomalyReason,
        },
      });
    }

    // Reset anomaly status for threats not in the response
    const flaggedThreatIds = anomalies.map((a: { threatId: string }) => a.threatId);
    for (const threat of threats) {
      if (!flaggedThreatIds.includes(threat.id)) {
        await db.threat.update({
          where: { id: threat.id },
          data: {
            isAnomaly: false,
            anomalyScore: null,
            evidence: null,
          },
        });
      }
    }

    return NextResponse.json({
      success: true,
      anomaliesDetected: anomalies.filter((a: any) => a.isAnomaly).length,
      totalAnalyzed: threats.length,
      anomalies: anomalies.filter((a: any) => a.isAnomaly),
    });
  } catch (error) {
    console.error('Error during anomaly detection:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
