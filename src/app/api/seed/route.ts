import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { Severity, ThreatType, ThreatStatus } from '@prisma/client';

const sampleThreats = [
  {
    title: 'SSH Brute Force Attack',
    description: 'Multiple failed SSH login attempts from external IP 192.168.1.100',
    severity: Severity.CRITICAL,
    type: ThreatType.INTRUSION,
    status: ThreatStatus.DETECTED,
    sourceIp: '192.168.1.100',
    destinationIp: '10.0.0.5',
    port: 22,
    protocol: 'SSH',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
    mitreTactics: 'Credential Access',
    mitreTechniques: 'Brute Force',
  },
  {
    title: 'Malware Download Detected',
    description: 'Suspicious file download from known malicious domain',
    severity: Severity.HIGH,
    type: ThreatType.MALWARE,
    status: ThreatStatus.INVESTIGATING,
    sourceIp: '192.168.1.45',
    destinationIp: '203.0.113.15',
    port: 80,
    protocol: 'HTTP',
    timestamp: new Date(Date.now() - 5 * 60 * 60 * 1000), // 5 hours ago
    mitreTactics: 'Initial Access',
    mitreTechniques: 'Drive-by Compromise',
  },
  {
    title: 'Phishing Email Clicked',
    description: 'Employee received and clicked phishing email link',
    severity: Severity.MEDIUM,
    type: ThreatType.PHISHING,
    status: ThreatStatus.RESOLVED,
    sourceIp: '192.168.1.32',
    destinationIp: '198.51.100.22',
    port: 25,
    protocol: 'SMTP',
    timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000), // 1 day ago
    assignedTo: 'asmith',
    mitreTactics: 'Initial Access',
    mitreTechniques: 'Spearphishing Link',
  },
  {
    title: 'Brute Force on Auth Server',
    description: 'Brute force attack detected on authentication server',
    severity: Severity.HIGH,
    type: ThreatType.INTRUSION,
    status: ThreatStatus.DETECTED,
    sourceIp: '203.0.113.45',
    destinationIp: '192.168.1.10',
    port: 22,
    protocol: 'SSH',
    timestamp: new Date(Date.now() - 1 * 60 * 60 * 1000), // 1 hour ago
    mitreTactics: 'Credential Access',
    mitreTechniques: 'Brute Force',
  },
  {
    title: 'DDoS Attack on DNS',
    description: 'DDoS attack detected on DNS server',
    severity: Severity.CRITICAL,
    type: ThreatType.DDOS,
    status: ThreatStatus.INVESTIGATING,
    sourceIp: '10.0.0.0/24',
    destinationIp: '192.168.1.200',
    port: 53,
    protocol: 'UDP',
    timestamp: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
    mitreTactics: 'Impact',
    mitreTechniques: 'Network Denial of Service',
  },
  {
    title: 'Data Exfiltration Detected',
    description: 'Large data transfer to external unknown IP address',
    severity: Severity.HIGH,
    type: ThreatType.DATA_EXFILTRATION,
    status: ThreatStatus.DETECTED,
    sourceIp: '192.168.1.88',
    destinationIp: '203.0.113.100',
    port: 443,
    protocol: 'HTTPS',
    timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000), // 3 hours ago
    assignedTo: 'bwilliams',
    mitreTactics: 'Exfiltration',
    mitreTechniques: 'Exfiltration Over Web Service',
  },
  {
    title: 'Lateral Movement Detected',
    description: 'Lateral movement detected - admin credential usage',
    severity: Severity.CRITICAL,
    type: ThreatType.INTRUSION,
    status: ThreatStatus.INVESTIGATING,
    sourceIp: '192.168.1.15',
    destinationIp: '192.168.1.25',
    port: 445,
    protocol: 'SMB',
    timestamp: new Date(Date.now() - 45 * 60 * 1000), // 45 minutes ago
    mitreTactics: 'Lateral Movement',
    mitreTechniques: 'Remote Services',
  },
  {
    title: 'Suspicious RDP Connection',
    description: 'Unusual RDP connection from non-admin workstation',
    severity: Severity.MEDIUM,
    type: ThreatType.SUSPICIOUS_BEHAVIOR,
    status: ThreatStatus.DETECTED,
    sourceIp: '192.168.1.67',
    destinationIp: '192.168.1.20',
    port: 3389,
    protocol: 'RDP',
    timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000), // 6 hours ago
    assignedTo: 'mgarcia',
  },
  {
    title: 'Suspicious File Execution',
    description: 'Suspicious file execution detected on workstation',
    severity: Severity.LOW,
    type: ThreatType.MALWARE,
    status: ThreatStatus.RESOLVED,
    sourceIp: '192.168.1.22',
    destinationIp: null,
    port: null,
    protocol: 'FILE',
    timestamp: new Date(Date.now() - 48 * 60 * 60 * 1000), // 2 days ago
    assignedTo: 'kjohnson',
  },
  {
    title: 'Phishing Site Access',
    description: 'Multiple users accessed known phishing site',
    severity: Severity.HIGH,
    type: ThreatType.PHISHING,
    status: ThreatStatus.INVESTIGATING,
    sourceIp: '192.168.1.91',
    destinationIp: '198.51.100.55',
    port: 80,
    protocol: 'HTTP',
    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000), // 4 hours ago
    mitreTactics: 'Initial Access',
    mitreTechniques: 'Spearphishing Link',
  },
  {
    title: 'Web App Brute Force',
    description: 'Failed login attempts on web application',
    severity: Severity.MEDIUM,
    type: ThreatType.INTRUSION,
    status: ThreatStatus.RESOLVED,
    sourceIp: '203.0.113.88',
    destinationIp: '192.168.1.30',
    port: 443,
    protocol: 'HTTPS',
    timestamp: new Date(Date.now() - 12 * 60 * 60 * 1000), // 12 hours ago
    mitreTactics: 'Credential Access',
    mitreTechniques: 'Brute Force',
  },
  {
    title: 'Privilege Escalation Attempt',
    description: 'Privilege escalation attempt detected on server',
    severity: Severity.HIGH,
    type: ThreatType.UNAUTHORIZED_ACCESS,
    status: ThreatStatus.DETECTED,
    sourceIp: '192.168.1.105',
    destinationIp: '10.0.0.50',
    port: 22,
    protocol: 'SSH',
    timestamp: new Date(Date.now() - 90 * 60 * 1000), // 90 minutes ago
    assignedTo: 'sysadmin',
    mitreTactics: 'Privilege Escalation',
    mitreTechniques: 'Exploitation for Privilege Escalation',
  },
  {
    title: 'Unauthorized Database Backup',
    description: 'Unauthorized database backup transfer detected',
    severity: Severity.CRITICAL,
    type: ThreatType.DATA_EXFILTRATION,
    status: ThreatStatus.INVESTIGATING,
    sourceIp: '192.168.1.33',
    destinationIp: '203.0.113.200',
    port: 21,
    protocol: 'FTP',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
    assignedTo: 'dbadmin',
    mitreTactics: 'Exfiltration',
    mitreTechniques: 'Data Transfer Size Limits',
  },
  {
    title: 'Ransomware Signature',
    description: 'Ransomware signature detected in network traffic',
    severity: Severity.HIGH,
    type: ThreatType.MALWARE,
    status: ThreatStatus.DETECTED,
    sourceIp: '192.168.1.56',
    destinationIp: '198.51.100.30',
    port: 80,
    protocol: 'HTTP',
    timestamp: new Date(Date.now() - 15 * 60 * 1000), // 15 minutes ago
    assignedTo: 'pmiller',
    mitreTactics: 'Impact',
    mitreTechniques: 'Data Encrypted for Impact',
  },
  {
    title: 'Unusual SMB Connection',
    description: 'Unusual SMB connection pattern detected',
    severity: Severity.HIGH,
    type: ThreatType.SUSPICIOUS_BEHAVIOR,
    status: ThreatStatus.INVESTIGATING,
    sourceIp: '192.168.1.12',
    destinationIp: '192.168.1.45',
    port: 445,
    protocol: 'SMB',
    timestamp: new Date(Date.now() - 8 * 60 * 60 * 1000), // 8 hours ago
    assignedTo: 'svc_account',
    mitreTactics: 'Lateral Movement',
    mitreTechniques: 'Remote Services',
  },
];

export async function GET() {
  try {
    // Check if data already exists
    const existingCount = await db.threat.count();
    if (existingCount > 0) {
      return NextResponse.json({
        success: true,
        message: `Database already contains ${existingCount} threats`,
        existing: true,
      });
    }

    // Insert sample threats
    for (const threat of sampleThreats) {
      await db.threat.create({
        data: {
          ...threat,
          isAnomaly: false,
          anomalyScore: null,
          confidence: null,
          evidence: null,
        },
      });
    }

    return NextResponse.json({
      success: true,
      message: `Successfully seeded ${sampleThreats.length} sample security threats`,
      count: sampleThreats.length,
    });
  } catch (error) {
    console.error('Error seeding data:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}
