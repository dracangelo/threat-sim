import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import ZAI from 'z-ai-web-dev-sdk'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { title, description, type, sourceIp, destinationIp, port, protocol } = body

    // Get recent threats for context
    const recentThreats = await db.threat.findMany({
      where: {
        type: type || undefined,
        timestamp: {
          gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // Last 7 days
        },
      },
      orderBy: { timestamp: 'desc' },
      take: 10,
    })

    // Use LLM to analyze for anomalies
    const zai = await ZAI.create()

    const threatContext = recentThreats.map(t => ({
      title: t.title,
      description: t.description,
      isAnomaly: t.isAnomaly,
      anomalyScore: t.anomalyScore,
      timestamp: t.timestamp,
    }))

    const analysisPrompt = `You are a cybersecurity threat analyst specializing in anomaly detection. Analyze the following new threat and determine if it represents anomalous behavior.

NEW THREAT:
- Title: ${title}
- Description: ${description}
- Type: ${type}
- Source IP: ${sourceIp || 'N/A'}
- Destination IP: ${destinationIp || 'N/A'}
- Port: ${port || 'N/A'}
- Protocol: ${protocol || 'N/A'}

RECENT SIMILAR THREATS (Last 7 Days):
${JSON.stringify(threatContext, null, 2)}

ANALYSIS CRITERIA:
1. Compare the new threat with recent similar threats
2. Look for unusual patterns in timing, geography, or behavior
3. Check if the threat characteristics deviate from baseline norms
4. Consider the severity and confidence levels of similar threats
5. Evaluate if this represents a new attack vector or escalation

Provide your analysis in the following JSON format ONLY:
{
  "isAnomaly": boolean,
  "anomalyScore": number (0-100),
  "confidence": number (0-100),
  "reasoning": string (brief explanation),
  "recommendations": string[] (array of actionable recommendations),
  "relatedMitreTactics": string[],
  "relatedMitreTechniques": string[]
}

Anomaly Score Guidelines:
- 0-30: Normal behavior within expected parameters
- 31-50: Slightly unusual but within acceptable range
- 51-70: Moderately anomalous, worth investigating
- 71-85: Highly anomalous, requires immediate attention
- 86-100: Extremely anomalous, critical priority`

    const completion = await zai.chat.completions.create({
      messages: [
        {
          role: 'assistant',
          content: 'You are a cybersecurity expert who provides analysis in strict JSON format.',
        },
        {
          role: 'user',
          content: analysisPrompt,
        },
      ],
      thinking: { type: 'disabled' },
    })

    const responseContent = completion.choices[0]?.message?.content

    // Parse the JSON response
    let analysis
    try {
      // Extract JSON from the response if there's extra text
      const jsonMatch = responseContent.match(/\{[\s\S]*\}/)
      const jsonStr = jsonMatch ? jsonMatch[0] : responseContent
      analysis = JSON.parse(jsonStr)
    } catch (error) {
      console.error('Failed to parse analysis response:', error)
      throw new Error('Invalid analysis response from AI')
    }

    // Convert scores to 0-1 range
    const anomalyScore = analysis.anomalyScore / 100
    const confidence = analysis.confidence / 100

    // Create the threat with AI analysis
    const threat = await db.threat.create({
      data: {
        title: body.title,
        description: body.description,
        severity: body.severity || 'MEDIUM',
        type: body.type,
        status: body.status || 'DETECTED',
        sourceIp: body.sourceIp,
        destinationIp: body.destinationIp,
        port: body.port,
        protocol: body.protocol,
        isAnomaly: analysis.isAnomaly,
        anomalyScore,
        confidence,
        mitreTactics: analysis.relatedMitreTactics?.join(', '),
        mitreTechniques: analysis.relatedMitreTechniques?.join(', '),
        evidence: JSON.stringify({
          aiReasoning: analysis.reasoning,
          recommendations: analysis.recommendations,
          similarThreatsCount: recentThreats.length,
        }),
      },
    })

    return NextResponse.json({
      threat,
      analysis: {
        ...analysis,
        recommendations: analysis.recommendations || [],
      },
    })
  } catch (error) {
    console.error('Error in anomaly detection:', error)
    return NextResponse.json(
      { error: 'Failed to perform anomaly detection', details: error.message },
      { status: 500 }
    )
  }
}
