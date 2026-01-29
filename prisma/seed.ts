import { PrismaClient, ThreatType, Severity, ThreatStatus, IOCType, UserRole, ChainType, ReportType } from '@prisma/client'

const prisma = new PrismaClient()

const ipGenerator = () => {
  return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
}

const internalIp = () => {
  return `${192}.${Math.floor(Math.random() * 168 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
}

const externalIp = () => {
  return `${Math.floor(Math.random() * 224 + 1)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
}

const hashGenerator = (type: 'MD5' | 'SHA1' | 'SHA256') => {
  const length = type === 'MD5' ? 32 : type === 'SHA1' ? 40 : 64
  const chars = '0123456789abcdef'
  let hash = ''
  for (let i = 0; i < length; i++) {
    hash += chars[Math.floor(Math.random() * chars.length)]
  }
  return hash
}

const users = [
  {
    username: 'jsmith',
    displayName: 'John Smith',
    email: 'john.smith@corp.local',
    role: UserRole.SENIOR_ANALYST,
    department: 'SOC Team',
    level: 3,
    skills: 'Malware Analysis, Incident Response, Threat Intelligence',
  },
  {
    username: 'mjones',
    displayName: 'Maria Jones',
    email: 'maria.jones@corp.local',
    role: UserRole.LEAD_ANALYST,
    department: 'SOC Team',
    level: 4,
    skills: 'Threat Hunting, SIEM, Digital Forensics',
  },
  {
    username: 'bwang',
    displayName: 'Brian Wang',
    email: 'brian.wang@corp.local',
    role: UserRole.ANALYST,
    department: 'SOC Team',
    level: 2,
    skills: 'Network Security, Log Analysis',
  },
  {
    username: 'slee',
    displayName: 'Sarah Lee',
    email: 'sarah.lee@corp.local',
    role: UserRole.INCIDENT_RESPONDER,
    department: 'Incident Response',
    level: 3,
    skills: 'Incident Response, Malware Analysis',
  },
  {
    username: 'dchen',
    displayName: 'David Chen',
    email: 'david.chen@corp.local',
    role: UserRole.THREAT_HUNTER,
    department: 'Threat Hunting',
    level: 4,
    skills: 'Advanced Threats, APT Analysis, MITRE ATT&CK',
  },
  {
    username: 'kmartinez',
    displayName: 'Karla Martinez',
    email: 'karla.martinez@corp.local',
    role: UserRole.SENIOR_ANALYST,
    department: 'SOC Team',
    level: 3,
    skills: 'Phishing Analysis, Email Security',
  },
  {
    username: 'rpatel',
    displayName: 'Raj Patel',
    email: 'raj.patel@corp.local',
    role: UserRole.SOC_MANAGER,
    department: 'Security Operations',
    level: 5,
    skills: 'Security Strategy, Team Management, Incident Response',
  },
  {
    username: 'lgarcia',
    displayName: 'Laura Garcia',
    email: 'laura.garcia@corp.local',
    role: UserRole.SECURITY_ENGINEER,
    department: 'Security Engineering',
    level: 4,
    skills: 'EDR, Endpoint Security, Automation',
  },
]

async function main() {
  console.log('Starting enhanced threat hunting data seeding with 50+ threats...')

  // Clear existing data
  await prisma.iOC.deleteMany()
  await prisma.timelineEvent.deleteMany()
  await prisma.threat.deleteMany()
  await prisma.securityEvent.deleteMany()
  await prisma.investigation.deleteMany()
  await prisma.incident.deleteMany()
  await prisma.huntingQuery.deleteMany()
  await prisma.analyticsData.deleteMany()
  await prisma.user.deleteMany()
  await prisma.correlationChain.deleteMany()
  await prisma.report.deleteMany()

  console.log('Cleared existing data')

  // Create Users
  console.log('Creating users...')
  const createdUsers = []
  for (const user of users) {
    const created = await prisma.user.create({
      data: user,
    })
    createdUsers.push(created)
    console.log(`  Created user: ${user.displayName} (${user.role})`)
  }

  // Create Correlation Chains
  console.log('\nCreating correlation chains...')
  const chains = []

  // APT29 (Cozy Bear) Multi-Stage Attack Chain
  const apt29Chain = await prisma.correlationChain.create({
    data: {
      chainName: 'APT29 Supply Chain Attack',
      description: 'Multi-stage attack attributed to APT29 (Cozy Bear) involving initial compromise through supply chain vulnerability, lateral movement, data staging, and exfiltration. Attack spans multiple weeks.',
      chainType: ChainType.MULTI_VECTOR,
      attackStage: 'Exfiltration',
      isApt: true,
      aptGroup: 'APT29 (Cozy Bear)',
      confidence: 0.92,
      isActive: true,
      startTime: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000),
      totalImpact: 'HIGH - Potential data exfiltration of sensitive intellectual property',
      affectedAssets: 'Build servers, Source code repositories, File servers, Domain controllers',
      metadata: JSON.stringify({
        attribution: 'APT29 (Cozy Bear)',
        timeframe: '14 days',
        techniques: 'T1195, T1059, T1021, T1041',
        victims: 'Software development team, Finance department',
      }),
    },
  })
  chains.push(apt29Chain)

  // APT41 Financial Fraud Chain
  const apt41Chain = await prisma.correlationChain.create({
    data: {
      chainName: 'APT41 Financial Fraud Campaign',
      description: 'Financially motivated attack attributed to APT41. Campaign involves credential theft, privilege escalation, lateral movement to financial systems, and fraudulent transaction attempts.',
      chainType: ChainType.MULTI_STAGE,
      attackStage: 'Execution',
      isApt: true,
      aptGroup: 'APT41',
      confidence: 0.88,
      isActive: true,
      startTime: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      totalImpact: 'CRITICAL - Active fraudulent transactions detected',
      affectedAssets: 'Financial systems, ERP, Database servers, User workstations',
      metadata: JSON.stringify({
        attribution: 'APT41',
        financialImpact: 'Estimated $500K+ attempted fraud',
        techniques: 'T1110, T1078, T1111, T1566',
      }),
    },
  })
  chains.push(apt41Chain)

  // Lateral Movement Chain
  const lateralChain = await prisma.correlationChain.create({
    data: {
      chainName: 'SMB Lateral Movement Campaign',
      description: 'Campaign showing lateral movement using SMB protocols from initial compromised workstation to multiple servers. Likely credential dumping and reuse.',
      chainType: ChainType.LATERAL_MOVEMENT,
      attackStage: 'Lateral Movement',
      isApt: false,
      confidence: 0.75,
      isActive: true,
      startTime: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
      totalImpact: 'MEDIUM - Multiple hosts potentially compromised',
      affectedAssets: '12 workstations, 4 servers, 2 domain controllers',
      metadata: JSON.stringify({
        initialCompromise: 'Phishing email',
        movementPath: 'WS-1234 → FS-01 → DC-01 → DB-01',
        techniques: 'T1021, T1077',
      }),
    },
  })
  chains.push(lateralChain)

  // Spear Phishing Chain
  const phishingChain = await prisma.correlationChain.create({
    data: {
      chainName: 'Spear Phishing Executive Campaign',
      description: 'Targeted spear phishing campaign against C-level executives. Multiple sophisticated emails with business-related pretext and malicious attachments. Shows high degree of victim reconnaissance.',
      chainType: ChainType.RECONNAISSANCE_EXPLOITATION,
      attackStage: 'Initial Access',
      isApt: false,
      confidence: 0.85,
      isActive: true,
      startTime: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      totalImpact: 'HIGH - Executive accounts at risk',
      affectedAssets: 'Email gateway, Executive workstations',
      metadata: JSON.stringify({
        targets: 'CEO, CFO, CTO, VP of Sales',
        emailCount: '15 emails delivered',
        attachmentTypes: 'Excel, Word, PDF',
        techniques: 'T1566, T1193',
      }),
    },
  })
  chains.push(phishingChain)

  // Ransomware Deployment Chain
  const ransomwareChain = await prisma.correlationChain.create({
    data: {
      chainName: 'Ryuk Ransomware Deployment',
      description: 'Ransomware attack chain showing initial access through RDP brute force, credential theft, privilege escalation, lateral movement, and eventual ransomware deployment affecting multiple systems.',
      chainType: ChainType.MULTI_STAGE,
      attackStage: 'Impact',
      isApt: false,
      confidence: 0.95,
      isActive: false,
      startTime: new Date(Date.now() - 21 * 24 * 60 * 60 * 1000),
      endTime: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      totalImpact: 'CRITICAL - 200+ systems encrypted',
      affectedAssets: 'File servers, Database servers, User workstations, Backup systems',
      metadata: JSON.stringify({
        ransomware: 'Ryuk',
        ransomDemand: '$2.5M',
        encryptedSystems: '234',
        businessImpact: 'Operations disrupted for 5 days',
      }),
    },
  })
  chains.push(ransomwareChain)

  console.log(`  Created ${chains.length} correlation chains`)

  // Create 50+ Threat Scenarios
  console.log('\nCreating 50+ threat scenarios...')
  const threatScenarios = [
    // APT29 Correlation Chain Threats (8 threats)
    {
      title: 'Supply Chain Compromise - Build Server',
      description: 'Suspicious software build process detected on build server. Unsigned binaries deployed with altered code. Signs of supply chain attack through build system compromise. Attackers modified build pipeline to inject malicious code.',
      type: ThreatType.SUPPLY_CHAIN,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: '10.0.0.100',
      sourcePort: 50000,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'SIEM',
      sourceSystem: 'Splunk',
      affectedHosts: 'BUILD-SRV-01.corp.local',
      affectedUsers: 'svc_build, admin_user',
      mitreTactics: 'Initial Access, Persistence',
      mitreTechniques: 'T1195, T1547',
      isAnomaly: true,
      anomalyScore: 0.94,
      confidence: 0.91,
      correlationChainId: apt29Chain.id,
      chainOrder: 1,
      priority: 1,
      assignedToId: createdUsers[4].id, // dchen - Threat Hunter
    },
    {
      title: 'Lateral Movement to Source Code Repos',
      description: 'SMB connections from compromised build server to source code repositories detected. Git credentials accessed from build process. Signs of lateral movement to access intellectual property.',
      type: ThreatType.LATERAL_MOVEMENT,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '10.0.0.100',
      destinationIp: '10.0.0.150',
      sourcePort: 50000,
      destinationPort: 22,
      protocol: 'SSH',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'Zeek',
      affectedHosts: 'GIT-01.corp.local, GIT-02.corp.local',
      mitreTactics: 'Lateral Movement, Collection',
      mitreTechniques: 'T1021, T1005',
      isAnomaly: true,
      anomalyScore: 0.89,
      confidence: 0.87,
      correlationChainId: apt29Chain.id,
      chainOrder: 2,
      priority: 1,
      assignedToId: createdUsers[4].id,
    },
    {
      title: 'Source Code Repository Access',
      description: 'Unusual access to source code repositories. Large number of repositories cloned by service account. Includes proprietary algorithms and product source code. Indicates IP theft.',
      type: ThreatType.DATA_EXFILTRATION,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '10.0.0.150',
      destinationIp: externalIp(),
      sourcePort: 50000,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'APPLICATION_LOGS',
      sourceSystem: 'GitLab',
      affectedHosts: 'GIT-01.corp.local',
      mitreTactics: 'Collection, Exfiltration',
      mitreTechniques: 'T1005, T1041',
      isAnomaly: true,
      anomalyScore: 0.95,
      confidence: 0.92,
      correlationChainId: apt29Chain.id,
      chainOrder: 3,
      priority: 1,
      assignedToId: createdUsers[4].id,
    },
    {
      title: 'PowerShell Execution on Domain Controller',
      description: 'Encoded PowerShell commands executed on domain controller. Commands include reconnaissance and credential dumping. Consistent with APT tradecraft for privilege escalation and credential theft.',
      type: ThreatType.COMMAND_AND_CONTROL,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: '10.0.0.5',
      sourcePort: 50000,
      destinationPort: 5985,
      protocol: 'HTTP',
      detectionMethod: 'EDR',
      sourceSystem: 'Microsoft Defender ATP',
      affectedHosts: 'DC-01.corp.local',
      affectedUsers: 'administrator, svc_domain',
      mitreTactics: 'Execution, Credential Access',
      mitreTechniques: 'T1059, T1003',
      isAnomaly: true,
      anomalyScore: 0.91,
      confidence: 0.89,
      correlationChainId: apt29Chain.id,
      chainOrder: 4,
      priority: 1,
      assignedToId: createdUsers[1].id, // mjones - Lead Analyst
    },
    {
      title: 'Data Staging on File Server',
      description: 'Large volumes of data copied to temporary staging directory on file server. Includes source code, design documents, and customer data. Pattern consistent with pre-exfiltration staging.',
      type: ThreatType.DATA_EXFILTRATION,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '10.0.0.150',
      destinationIp: '10.0.0.200',
      sourcePort: 50000,
      destinationPort: 445,
      protocol: 'SMB',
      detectionMethod: 'EDR',
      sourceSystem: 'CrowdStrike Falcon',
      affectedHosts: 'FS-01.corp.local',
      mitreTactics: 'Collection, Staging',
      mitreTechniques: 'T1074, T1005',
      isAnomaly: true,
      anomalyScore: 0.87,
      confidence: 0.84,
      correlationChainId: apt29Chain.id,
      chainOrder: 5,
      priority: 2,
    },
    {
      title: 'Encrypted Exfiltration to External IP',
      description: 'Large outbound encrypted data transfer to external IP address. Data matches staging volume (15GB+). Transfer occurred during non-business hours. Patterns match APT exfiltration techniques.',
      type: ThreatType.DATA_EXFILTRATION,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '10.0.0.200',
      destinationIp: externalIp(),
      sourcePort: 50000,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'Darktrace',
      affectedHosts: 'FS-01.corp.local',
      mitreTactics: 'Exfiltration',
      mitreTechniques: 'T1041, T1567',
      isAnomaly: true,
      anomalyScore: 0.96,
      confidence: 0.93,
      correlationChainId: apt29Chain.id,
      chainOrder: 6,
      priority: 1,
      assignedToId: createdUsers[3].id, // slee - Incident Responder
    },
    {
      title: 'Credential Dumping Memory Artifacts',
      description: 'Mimikatz-like activity detected on multiple hosts. Attackers dumping credentials from LSASS memory. Credentials used for lateral movement and persistence.',
      type: ThreatType.CREDENTIAL_THEFT,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'EDR',
      sourceSystem: 'Carbon Black',
      affectedHosts: 'WS-2345.corp.local, WS-3456.corp.local, WS-4567.corp.local',
      mitreTactics: 'Credential Access',
      mitreTechniques: 'T1003, T1552',
      isAnomaly: true,
      anomalyScore: 0.92,
      confidence: 0.88,
      correlationChainId: apt29Chain.id,
      chainOrder: 7,
      priority: 1,
      assignedToId: createdUsers[3].id,
    },
    {
      title: 'Persistence via Scheduled Tasks',
      description: 'Multiple scheduled tasks created for persistence. Tasks execute malicious PowerShell scripts every 30 minutes. Tasks named to blend in with legitimate system tasks.',
      type: ThreatType.PERSISTENCE,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'EDR',
      sourceSystem: 'SentinelOne',
      affectedHosts: 'WS-1234.corp.local, WS-2345.corp.local',
      mitreTactics: 'Persistence',
      mitreTechniques: 'T1053, T1543',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.79,
      correlationChainId: apt29Chain.id,
      chainOrder: 8,
      priority: 2,
    },

    // APT41 Correlation Chain Threats (7 threats)
    {
      title: 'Office 365 Password Spraying',
      description: 'Password spraying attack against Office 365 from external IP. Attackers testing common passwords across multiple user accounts. Focus on finance department accounts. Lockout policies triggered.',
      type: ThreatType.UNAUTHORIZED_ACCESS,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: externalIp(),
      destinationIp: 'office365.com',
      sourcePort: null,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'IAM',
      sourceSystem: 'Microsoft Azure AD',
      affectedUsers: 'finance_1@corp.local, finance_2@corp.local, finance_3@corp.local',
      mitreTactics: 'Credential Access, Initial Access',
      mitreTechniques: 'T1110.003',
      isAnomaly: true,
      anomalyScore: 0.88,
      confidence: 0.91,
      correlationChainId: apt41Chain.id,
      chainOrder: 1,
      priority: 2,
      assignedToId: createdUsers[5].id, // kmartinez - Phishing Analyst
    },
    {
      title: 'Successful Finance Account Compromise',
      description: 'Successful authentication to finance department user account from external IP geolocated to high-risk country. Account immediately accessed ERP system and financial reporting tools.',
      type: ThreatType.UNAUTHORIZED_ACCESS,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: externalIp(),
      destinationIp: 'erp.corp.local',
      sourcePort: 50000,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'IAM',
      sourceSystem: 'SAP ERP',
      affectedUsers: 'finance_manager@corp.local',
      mitreTactics: 'Initial Access',
      mitreTechniques: 'T1078',
      isAnomaly: true,
      anomalyScore: 0.94,
      confidence: 0.89,
      correlationChainId: apt41Chain.id,
      chainOrder: 2,
      priority: 1,
      assignedToId: createdUsers[6].id, // rpatel - SOC Manager
    },
    {
      title: 'ERP System Fraudulent Transactions',
      description: 'Multiple fraudulent payment transactions initiated in ERP system. Transactions to new vendors created same day. Amounts just below approval thresholds to avoid detection.',
      type: ThreatType.INTRUSION,
      severity: Severity.CRITICAL,
      status: ThreatStatus.CONTAINED,
      sourceIp: '10.0.0.50',
      destinationIp: '10.0.0.60',
      sourcePort: 50000,
      destinationPort: 8000,
      protocol: 'HTTPS',
      detectionMethod: 'APPLICATION_LOGS',
      sourceSystem: 'SAP ERP',
      affectedHosts: 'ERP-APP-01.corp.local',
      mitreTactics: 'Impact',
      mitreTechniques: 'T1659',
      isAnomaly: true,
      anomalyScore: 0.97,
      confidence: 0.95,
      correlationChainId: apt41Chain.id,
      chainOrder: 3,
      priority: 1,
      assignedToId: createdUsers[6].id,
    },
    {
      title: 'Bank Account Modification Attempts',
      description: 'Attempts to modify vendor bank account information in ERP system. Modifications intercepted by controls but indicate fraud attempt. Target accounts: $450K total payments pending.',
      type: ThreatType.INTRUSION,
      severity: Severity.CRITICAL,
      status: ThreatStatus.CONTAINED,
      sourceIp: '10.0.0.50',
      destinationIp: '10.0.0.60',
      sourcePort: 50000,
      destinationPort: 8000,
      protocol: 'HTTPS',
      detectionMethod: 'APPLICATION_LOGS',
      sourceSystem: 'SAP ERP',
      mitreTactics: 'Impact',
      mitreTechniques: 'T1659',
      isAnomaly: true,
      anomalyScore: 0.95,
      confidence: 0.92,
      correlationChainId: apt41Chain.id,
      chainOrder: 4,
      priority: 1,
      assignedToId: createdUsers[6].id,
    },
    {
      title: 'Privilege Escalation in ERP',
      description: 'Privilege escalation detected in ERP system. Finance account assigned temporary admin privileges without proper approval. Used to attempt payment approvals.',
      type: ThreatType.PRIVILEGE_ESCALATION,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '10.0.0.50',
      destinationIp: '10.0.0.60',
      sourcePort: 50000,
      destinationPort: 8000,
      protocol: 'HTTPS',
      detectionMethod: 'IAM',
      sourceSystem: 'SAP ERP',
      affectedUsers: 'finance_manager@corp.local',
      mitreTactics: 'Privilege Escalation',
      mitreTechniques: 'T1078, T1548',
      isAnomaly: true,
      anomalyScore: 0.91,
      confidence: 0.86,
      correlationChainId: apt41Chain.id,
      chainOrder: 5,
      priority: 2,
    },
    {
      title: 'Financial Data Download',
      description: 'Large export of financial data from ERP system. Includes vendor master data, payment history, and bank account information. Data exported to CSV format.',
      type: ThreatType.DATA_EXFILTRATION,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '10.0.0.60',
      destinationIp: externalIp(),
      sourcePort: 50000,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'DLP',
      sourceSystem: 'Symantec DLP',
      affectedHosts: 'ERP-APP-01.corp.local',
      mitreTactics: 'Collection, Exfiltration',
      mitreTechniques: 'T1005, T1041',
      isAnomaly: true,
      anomalyScore: 0.89,
      confidence: 0.88,
      correlationChainId: apt41Chain.id,
      chainOrder: 6,
      priority: 2,
    },
    {
      title: 'ERP System Backdoor Creation',
      description: 'Backdoor script detected on ERP application server. Script allows remote command execution and data access. Placed in system directory with legitimate name.',
      type: ThreatType.MALWARE,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'EDR',
      sourceSystem: 'CrowdStrike Falcon',
      affectedHosts: 'ERP-APP-01.corp.local',
      mitreTactics: 'Persistence, Execution',
      mitreTechniques: 'T1505, T1059',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.85,
      correlationChainId: apt41Chain.id,
      chainOrder: 7,
      priority: 1,
      assignedToId: createdUsers[7].id, // lgarcia - Security Engineer
    },

    // Spear Phishing Executive Campaign Threats (6 threats)
    {
      title: 'Spear Phishing Email - CEO Target',
      description: 'Sophisticated spear phishing email targeting CEO. Email appears to be from Board Chair regarding urgent acquisition review. Contains malicious Excel document with macro. Sender domain typo-squatted.',
      type: ThreatType.SPEAR_PHISHING,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: externalIp(),
      destinationIp: '10.0.0.50',
      sourcePort: null,
      destinationPort: 25,
      protocol: 'SMTP',
      detectionMethod: 'EMAIL_SECURITY',
      sourceSystem: 'Mimecast',
      affectedUsers: 'ceo@corp.local',
      mitreTactics: 'Initial Access',
      mitreTechniques: 'T1566.001',
      isAnomaly: true,
      anomalyScore: 0.86,
      confidence: 0.84,
      correlationChainId: phishingChain.id,
      chainOrder: 1,
      priority: 2,
      assignedToId: createdUsers[5].id, // kmartinez
    },
    {
      title: 'Spear Phishing Email - CFO Target',
      description: 'Targeted spear phishing email sent to CFO. Email references upcoming financial audit and requests review of attached document. PDF file with embedded exploit.',
      type: ThreatType.SPEAR_PHISHING,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: externalIp(),
      destinationIp: '10.0.0.50',
      sourcePort: null,
      destinationPort: 25,
      protocol: 'SMTP',
      detectionMethod: 'EMAIL_SECURITY',
      sourceSystem: 'Mimecast',
      affectedUsers: 'cfo@corp.local',
      mitreTactics: 'Initial Access',
      mitreTechniques: 'T1566.001',
      isAnomaly: true,
      anomalyScore: 0.84,
      confidence: 0.82,
      correlationChainId: phishingChain.id,
      chainOrder: 2,
      priority: 2,
      assignedToId: createdUsers[5].id,
    },
    {
      title: 'Macro Execution on Executive Workstation',
      description: 'Excel macro executed on CFO workstation after opening spear phishing email. Macro attempts to download and execute malicious payload from external domain.',
      type: ThreatType.MALWARE,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: externalIp(),
      sourcePort: 50000,
      destinationPort: 80,
      protocol: 'HTTP',
      detectionMethod: 'EDR',
      sourceSystem: 'Microsoft Defender ATP',
      affectedHosts: 'WS-CEO-01.corp.local',
      affectedUsers: 'cfo@corp.local',
      mitreTactics: 'Execution',
      mitreTechniques: 'T1566, T1204',
      isAnomaly: true,
      anomalyScore: 0.90,
      confidence: 0.87,
      correlationChainId: phishingChain.id,
      chainOrder: 3,
      priority: 1,
      assignedToId: createdUsers[3].id, // slee
    },
    {
      title: 'Web Shell Deployment on Web Server',
      description: 'Web shell uploaded to public-facing web server. Shell allows remote command execution and file access. Upload follows phishing email opening patterns.',
      type: ThreatType.WEB_APPLICATION_ATTACK,
      severity: Severity.CRITICAL,
      status: ThreatStatus.CONTAINED,
      sourceIp: externalIp(),
      destinationIp: '203.0.113.50',
      sourcePort: null,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'WAF',
      sourceSystem: 'AWS WAF',
      affectedHosts: 'WEB-01.corp.local',
      mitreTactics: 'Persistence, Execution',
      mitreTechniques: 'T1505, T1190',
      isAnomaly: true,
      anomalyScore: 0.93,
      confidence: 0.91,
      correlationChainId: phishingChain.id,
      chainOrder: 4,
      priority: 1,
      assignedToId: createdUsers[7].id, // lgarcia
    },
    {
      title: 'Email Credential Theft',
      description: 'Email credentials harvested from multiple executive accounts. Credentials captured via phishing pages or credential stealer malware. Used to access email inboxes.',
      type: ThreatType.CREDENTIAL_THEFT,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: externalIp(),
      destinationIp: 'office365.com',
      sourcePort: null,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'IAM',
      sourceSystem: 'Microsoft Azure AD',
      affectedUsers: 'ceo@corp.local, cfo@corp.local, cto@corp.local',
      mitreTactics: 'Credential Access',
      mitreTechniques: 'T1110, T1552',
      isAnomaly: true,
      anomalyScore: 0.88,
      confidence: 0.90,
      correlationChainId: phishingChain.id,
      chainOrder: 5,
      priority: 2,
    },
    {
      title: 'Business Email Compromise - Wire Transfer',
      description: 'Business email compromise attempt detected. Compromised CFO account used to send fraudulent wire transfer instructions to finance team. Request for $150K transfer to new vendor.',
      type: ThreatType.BUSINESS_EMAIL_COMPROMISE,
      severity: Severity.CRITICAL,
      status: ThreatStatus.CONTAINED,
      sourceIp: 'office365.com',
      destinationIp: '10.0.0.50',
      sourcePort: null,
      destinationPort: 25,
      protocol: 'SMTP',
      detectionMethod: 'EMAIL_SECURITY',
      sourceSystem: 'Mimecast',
      affectedUsers: 'cfo@corp.local, finance_team@corp.local',
      mitreTactics: 'Social Engineering',
      mitreTechniques: 'T1566, T1659',
      isAnomaly: true,
      anomalyScore: 0.92,
      confidence: 0.94,
      correlationChainId: phishingChain.id,
      chainOrder: 6,
      priority: 1,
      assignedToId: createdUsers[6].id, // rpatel
    },

    // Lateral Movement Campaign Threats (5 threats)
    {
      title: 'SMB Lateral Movement Workstation to File Server',
      description: 'Suspicious SMB connections from compromised workstation to file servers. Admin credentials used from non-admin workstation. Attempt to enumerate file shares.',
      type: ThreatType.LATERAL_MOVEMENT,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '192.168.1.123',
      destinationIp: '10.0.0.200',
      sourcePort: 50000,
      destinationPort: 445,
      protocol: 'SMB',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'Zeek',
      affectedHosts: 'FS-01.corp.local',
      affectedUsers: 'administrator',
      mitreTactics: 'Lateral Movement',
      mitreTechniques: 'T1021.002',
      isAnomaly: true,
      anomalyScore: 0.81,
      confidence: 0.78,
      correlationChainId: lateralChain.id,
      chainOrder: 1,
      priority: 2,
    },
    {
      title: 'Remote Desktop to Domain Controller',
      description: 'RDP connection from compromised workstation to domain controller using admin credentials. Connection timing correlates with credential dumping activity.',
      type: ThreatType.LATERAL_MOVEMENT,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '192.168.1.123',
      destinationIp: '10.0.0.5',
      sourcePort: 50000,
      destinationPort: 3389,
      protocol: 'RDP',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'Wireshark',
      affectedHosts: 'DC-01.corp.local',
      affectedUsers: 'administrator',
      mitreTactics: 'Lateral Movement',
      mitreTechniques: 'T1021.001',
      isAnomaly: true,
      anomalyScore: 0.87,
      confidence: 0.85,
      correlationChainId: lateralChain.id,
      chainOrder: 2,
      priority: 1,
      assignedToId: createdUsers[4].id, // dchen
    },
    {
      title: 'WinRM Service Execution',
      description: 'WinRM commands executed on multiple servers from compromised workstation. Commands include service enumeration and file operations. Pattern suggests automated lateral movement.',
      type: ThreatType.LATERAL_MOVEMENT,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '192.168.1.123',
      destinationIp: '10.0.0.30',
      sourcePort: 50000,
      destinationPort: 5985,
      protocol: 'HTTP',
      detectionMethod: 'SIEM',
      sourceSystem: 'Splunk',
      affectedHosts: 'APP-SRV-01.corp.local, DB-SRV-01.corp.local',
      mitreTactics: 'Execution, Lateral Movement',
      mitreTechniques: 'T1021.006, T1059',
      isAnomaly: true,
      anomalyScore: 0.84,
      confidence: 0.81,
      correlationChainId: lateralChain.id,
      chainOrder: 3,
      priority: 2,
    },
    {
      title: 'Pass-the-Hash Authentication',
      description: 'Pass-the-hash authentication attempts detected on multiple hosts. Attackers reusing NTLM hashes stolen from compromised workstation. Successful authentication to 4 servers.',
      type: ThreatType.LATERAL_MOVEMENT,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '192.168.1.123',
      destinationIp: '10.0.0.40',
      sourcePort: 50000,
      destinationPort: 445,
      protocol: 'SMB',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'Darktrace',
      affectedHosts: 'APP-SRV-02.corp.local, DB-SRV-02.corp.local, WEB-SRV-01.corp.local',
      mitreTactics: 'Credential Access, Lateral Movement',
      mitreTechniques: 'T1550.002',
      isAnomaly: true,
      anomalyScore: 0.89,
      confidence: 0.86,
      correlationChainId: lateralChain.id,
      chainOrder: 4,
      priority: 1,
      assignedToId: createdUsers[1].id, // mjones
    },
    {
      title: 'Scheduled Task Remote Creation',
      description: 'Remote creation of scheduled tasks on multiple servers via WinRM. Tasks configured to execute PowerShell with encoded commands every hour. Persistence mechanism deployment.',
      type: ThreatType.PERSISTENCE,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: '192.168.1.123',
      destinationIp: '10.0.0.30',
      sourcePort: 50000,
      destinationPort: 5985,
      protocol: 'HTTP',
      detectionMethod: 'EDR',
      sourceSystem: 'SentinelOne',
      affectedHosts: 'APP-SRV-01.corp.local, DB-SRV-01.corp.local',
      mitreTactics: 'Persistence',
      mitreTechniques: 'T1053.005',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.76,
      correlationChainId: lateralChain.id,
      chainOrder: 5,
      priority: 2,
    },

    // Additional diverse threats (24+ threats)
    {
      title: 'Ransomware Ryuk Deployment - File Server',
      description: 'Ryuk ransomware detected on file server. Encryption of files in progress. Ransom note dropped. Files with extensions encrypted. Backup server also targeted.',
      type: ThreatType.RANSOMWARE,
      severity: Severity.CRITICAL,
      status: ThreatStatus.RESOLVED,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'EDR',
      sourceSystem: 'CrowdStrike Falcon',
      affectedHosts: 'FS-01.corp.local, BACKUP-01.corp.local',
      mitreTactics: 'Impact',
      mitreTechniques: 'T1486',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.98,
      correlationChainId: ransomwareChain.id,
      chainOrder: 6,
      priority: 1,
      assignedToId: createdUsers[3].id, // slee
      resolvedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      resolvedBy: 'slee',
    },
    {
      title: 'RDP Brute Force - VPN Gateway',
      description: 'RDP brute force attack detected against VPN gateway. 50,000+ failed authentication attempts from multiple IPs. Lockout policies triggered. Attack shows automation.',
      type: ThreatType.UNAUTHORIZED_ACCESS,
      severity: Severity.MEDIUM,
      status: ThreatStatus.CONTAINED,
      sourceIp: externalIp(),
      destinationIp: '10.0.0.1',
      sourcePort: null,
      destinationPort: 3389,
      protocol: 'RDP',
      detectionMethod: 'IDS',
      sourceSystem: 'Cisco ASA',
      mitreTactics: 'Credential Access',
      mitreTechniques: 'T1110.001',
      isAnomaly: true,
      anomalyScore: 0.72,
      confidence: 0.85,
      priority: 3,
    },
    {
      title: 'SQL Injection - Customer Portal',
      description: 'SQL injection attack patterns detected in customer portal logs. Attackers attempting to extract customer data via UNION-based injection. Multiple payload variations tested.',
      type: ThreatType.WEB_APPLICATION_ATTACK,
      severity: Severity.MEDIUM,
      status: ThreatStatus.CONTAINED,
      sourceIp: externalIp(),
      destinationIp: '203.0.113.100',
      sourcePort: null,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'WAF',
      sourceSystem: 'AWS WAF',
      mitreTactics: 'Initial Access',
      mitreTechniques: 'T1190',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.82,
      priority: 3,
    },
    {
      title: 'Cryptomining Detected',
      description: 'Cryptocurrency mining process detected on application server. Using 95% CPU and consuming significant resources. Mining Monero (XMR) using public pool.',
      type: ThreatType.RESOURCE_HIJACKING,
      severity: Severity.MEDIUM,
      status: ThreatStatus.CONTAINED,
      sourceIp: internalIp(),
      destinationIp: externalIp(),
      sourcePort: 50000,
      destinationPort: 3333,
      protocol: 'TCP',
      detectionMethod: 'EDR',
      sourceSystem: 'SentinelOne',
      affectedHosts: 'APP-SRV-05.corp.local',
      mitreTactics: 'Resource Development, Impact',
      mitreTechniques: 'T1496',
      isAnomaly: true,
      anomalyScore: 0.78,
      confidence: 0.84,
      priority: 3,
    },
    {
      title: 'Data Exfiltration via Cloud Storage',
      description: 'Large file upload to personal cloud storage account from corporate workstation. 5GB of proprietary code uploaded to Google Drive. User account shows anomalous behavior.',
      type: ThreatType.DATA_EXFILTRATION,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: 'drive.google.com',
      sourcePort: 50000,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'DLP',
      sourceSystem: 'Symantec DLP',
      affectedHosts: 'WS-9876.corp.local',
      affectedUsers: 'dev_user@corp.local',
      mitreTactics: 'Exfiltration',
      mitreTechniques: 'T1567.001',
      isAnomaly: true,
      anomalyScore: 0.83,
      confidence: 0.86,
      priority: 2,
      assignedToId: createdUsers[2].id, // bwang
    },
    {
      title: 'Insider Threat - Data Access',
      description: 'Unusual data access pattern detected by employee with scheduled departure. Accessed 50GB of customer data in past week. Normal access is <1GB/month. Potential data theft.',
      type: ThreatType.SUSPICIOUS_BEHAVIOR,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: '10.0.0.200',
      sourcePort: 50000,
      destinationPort: 445,
      protocol: 'SMB',
      detectionMethod: 'UEBA',
      sourceSystem: 'Exabeam',
      affectedHosts: 'FS-01.corp.local',
      affectedUsers: 'leaving_employee@corp.local',
      mitreTactics: 'Collection',
      mitreTechniques: 'T1005',
      isAnomaly: true,
      anomalyScore: 0.91,
      confidence: 0.88,
      priority: 2,
      assignedToId: createdUsers[1].id, // mjones
    },
    {
      title: 'Supply Chain Compromise - Third-Party Library',
      description: 'Malicious third-party library detected in application dependencies. Library contains backdoor allowing remote code execution. Used in critical application.',
      type: ThreatType.SUPPLY_CHAIN,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'SCA',
      sourceSystem: 'Snyk',
      affectedHosts: 'APP-SRV-01.corp.local, APP-SRV-02.corp.local',
      mitreTactics: 'Initial Access, Persistence',
      mitreTechniques: 'T1195.002',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.89,
      priority: 1,
      assignedToId: createdUsers[7].id, // lgarcia
    },
    {
      title: 'DNS Tunneling Detected',
      description: 'DNS tunneling activity detected. Excessive DNS queries to suspicious domain. Query patterns contain encoded data. Possible C2 channel.',
      type: ThreatType.COMMAND_AND_CONTROL,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: '8.8.8.8',
      sourcePort: null,
      destinationPort: 53,
      protocol: 'DNS',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'FireEye',
      affectedHosts: 'WS-5432.corp.local',
      mitreTactics: 'Command and Control',
      mitreTechniques: 'T1071.004',
      isAnomaly: true,
      anomalyScore: 0.86,
      confidence: 0.83,
      priority: 2,
    },
    {
      title: 'Zero-Day Exploit Attempt - Browser',
      description: 'Zero-day exploit attempt targeting browser vulnerability observed. Exploit payload targeting unpatched vulnerability. No public exploit exists yet.',
      type: ThreatType.ZERO_DAY,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: externalIp(),
      destinationIp: '10.0.0.80',
      sourcePort: null,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'WAF',
      sourceSystem: 'Akamai WAF',
      affectedHosts: 'WEB-02.corp.local',
      mitreTactics: 'Initial Access',
      mitreTechniques: 'T1190',
      isAnomaly: true,
      anomalyScore: 0.97,
      confidence: 0.79,
      priority: 1,
      assignedToId: createdUsers[4].id, // dchen
    },
    {
      title: 'USB Device Attack',
      description: 'Unauthorized USB device connected to secure workstation. Contains autorun.inf and suspicious executable. Potential badUSB or HID-based attack.',
      type: ThreatType.INTRUSION,
      severity: Severity.MEDIUM,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: null,
      destinationIp: null,
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'EDR',
      sourceSystem: 'Carbon Black',
      affectedHosts: 'WS-SECURE-01.corp.local',
      mitreTactics: 'Initial Access',
      mitreTechniques: 'T1091',
      isAnomaly: true,
      anomalyScore: 0.75,
      confidence: 0.81,
      priority: 3,
    },
    {
      title: 'Living off the Land - LOLBins',
      description: 'Living off the Land techniques detected. Attackers using legitimate system tools (certutil, bitsadmin, powershell) for malicious purposes. No malware files on disk.',
      type: ThreatType.DEFENSE_EVASION,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'EDR',
      sourceSystem: 'CrowdStrike Falcon',
      affectedHosts: 'WS-3456.corp.local',
      mitreTactics: 'Defense Evasion, Execution',
      mitreTechniques: 'T1218, T1059',
      isAnomaly: true,
      anomalyScore: 0.82,
      confidence: 0.80,
      priority: 2,
    },
    {
      title: 'Reconnaissance Activity - Port Scanning',
      description: 'Port scanning activity detected from external IP. Scanning corporate network for open ports and services. Fingerprinting web servers and applications.',
      type: ThreatType.RECONNAISSANCE,
      severity: Severity.MEDIUM,
      status: ThreatStatus.MONITORING,
      sourceIp: externalIp(),
      destinationIp: '203.0.113.0/24',
      sourcePort: null,
      destinationPort: null,
      protocol: 'TCP',
      detectionMethod: 'IDS',
      sourceSystem: 'Snort',
      mitreTactics: 'Reconnaissance',
      mitreTechniques: 'T1046',
      isAnomaly: true,
      anomalyScore: 0.68,
      confidence: 0.75,
      priority: 3,
    },
    {
      title: 'API Abuse - Rate Limiting',
      description: 'API abuse detected. Excessive API calls to customer data endpoint. Attempting to enumerate customer database. Rate limiting triggered.',
      type: ThreatType.INTRUSION,
      severity: Severity.MEDIUM,
      status: ThreatStatus.CONTAINED,
      sourceIp: externalIp(),
      destinationIp: 'api.corp.local',
      sourcePort: null,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'API_GATEWAY',
      sourceSystem: 'Kong',
      mitreTactics: 'Discovery',
      mitreTechniques: 'T1083',
      isAnomaly: true,
      anomalyScore: 0.73,
      confidence: 0.87,
      priority: 3,
    },
    {
      title: 'Social Engineering - Vishing',
      description: 'Vishing (voice phishing) campaign detected. Attackers calling employees claiming to be IT support. Attempting to obtain credentials for "password reset".',
      type: ThreatType.SOCIAL_ENGINEERING,
      severity: Severity.MEDIUM,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: null,
      destinationIp: null,
      sourcePort: null,
      destinationPort: null,
      protocol: 'VOICE',
      detectionMethod: 'REPORTING',
      sourceSystem: 'User Reports',
      affectedUsers: 'hr_dept@corp.local, finance_dept@corp.local',
      mitreTactics: 'Initial Access',
      mitreTechniques: 'T1566',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.70,
      priority: 3,
      assignedToId: createdUsers[5].id, // kmartinez
    },
    {
      title: 'Container Escape Attempt',
      description: 'Container escape attempt detected in Kubernetes cluster. Attackers exploiting container runtime vulnerability. Attempted access to host file system.',
      type: ThreatType.PRIVILEGE_ESCALATION,
      severity: Severity.HIGH,
      status: ThreatStatus.CONTAINED,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'CSP',
      sourceSystem: 'Aqua Security',
      affectedHosts: 'K8S-NODE-01, K8S-NODE-02',
      mitreTactics: 'Privilege Escalation',
      mitreTechniques: 'T1611',
      isAnomaly: true,
      anomalyScore: 0.88,
      confidence: 0.85,
      priority: 2,
      assignedToId: createdUsers[7].id, // lgarcia
    },
    {
      title: 'Cloud Misconfiguration - S3 Bucket',
      description: 'S3 bucket misconfiguration detected. Public access enabled on sensitive data bucket. Bucket contains customer PII. Access logs show external access.',
      type: ThreatType.DATA_EXFILTRATION,
      severity: Severity.CRITICAL,
      status: ThreatStatus.RESOLVED,
      sourceIp: externalIp(),
      destinationIp: 's3.amazonaws.com',
      sourcePort: null,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'CSPM',
      sourceSystem: 'Prisma Cloud',
      affectedHosts: 'AWS S3',
      mitreTactics: 'Discovery',
      mitreTechniques: 'T1530',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.99,
      priority: 1,
      assignedToId: createdUsers[7].id, // lgarcia
      resolvedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      resolvedBy: 'lgarcia',
    },
    {
      title: 'Man-in-the-Middle Attack',
      description: 'Man-in-the-Middle attack detected on internal network. ARP poisoning observed between workstation and gateway. Certificate errors reported.',
      type: ThreatType.INTRUSION,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: '10.0.0.1',
      sourcePort: null,
      destinationPort: null,
      protocol: 'ARP',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'SolarWinds NPM',
      affectedHosts: 'WS-5678.corp.local',
      mitreTactics: 'Credential Access',
      mitreTechniques: 'T1557',
      isAnomaly: true,
      anomalyScore: 0.84,
      confidence: 0.82,
      priority: 2,
    },
    {
      title: 'Fileless Malware - Registry',
      description: 'Fileless malware technique using registry for persistence. Malicious code stored in registry keys and executed via regsvr32. No files on disk.',
      type: ThreatType.MALWARE,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'EDR',
      sourceSystem: 'Microsoft Defender ATP',
      affectedHosts: 'WS-7890.corp.local',
      mitreTactics: 'Persistence, Defense Evasion',
      mitreTechniques: 'T1547.001, T1112',
      isAnomaly: true,
      anomalyScore: 0.80,
      confidence: 0.78,
      priority: 2,
    },
    {
      title: 'DDoS Volumetric Attack',
      description: 'Volumetric DDoS attack on public-facing API. 100GB+ traffic from botnet of 10,000+ IPs. Application partially unavailable. CDN mitigation active.',
      type: ThreatType.DDOS,
      severity: Severity.HIGH,
      status: ThreatStatus.CONTAINED,
      sourceIp: externalIp(),
      destinationIp: '203.0.113.50',
      sourcePort: null,
      destinationPort: 443,
      protocol: 'TCP',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'Cloudflare',
      mitreTactics: 'Impact',
      mitreTechniques: 'T1498',
      isAnomaly: false,
      anomalyScore: null,
      confidence: 0.99,
      priority: 2,
    },
    {
      title: 'Process Hollowing Detected',
      description: 'Process hollowing technique detected. Malware suspends legitimate process, unmaps its memory, and injects malicious code. Advanced evasion technique.',
      type: ThreatType.MALWARE,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: internalIp(),
      sourcePort: null,
      destinationPort: null,
      protocol: 'LOCAL',
      detectionMethod: 'EDR',
      sourceSystem: 'SentinelOne',
      affectedHosts: 'WS-8901.corp.local',
      mitreTactics: 'Defense Evasion, Privilege Escalation',
      mitreTechniques: 'T1055.012',
      isAnomaly: true,
      anomalyScore: 0.93,
      confidence: 0.86,
      priority: 1,
      assignedToId: createdUsers[3].id, // slee
    },
    {
      title: 'Supply Chain Attack - CI/CD Pipeline',
      description: 'CI/CD pipeline compromise detected. Malicious code injected during build process. All builds from past 48 hours potentially affected. Downstream customers impacted.',
      type: ThreatType.SUPPLY_CHAIN,
      severity: Severity.CRITICAL,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: '10.0.0.100',
      sourcePort: 50000,
      destinationPort: 443,
      protocol: 'HTTPS',
      detectionMethod: 'SIEM',
      sourceSystem: 'Splunk',
      affectedHosts: 'BUILD-SRV-01.corp.local',
      mitreTactics: 'Persistence, Initial Access',
      mitreTechniques: 'T1195, T1199',
      isAnomaly: true,
      anomalyScore: 0.96,
      confidence: 0.91,
      priority: 1,
      assignedToId: createdUsers[6].id, // rpatel
    },
    {
      title: 'Kerberoasting Attack',
      description: 'Kerberoasting attack detected. Attackers requesting service principal name (SPN) tickets for offline cracking. Targeting high-privilege service accounts.',
      type: ThreatType.CREDENTIAL_THEFT,
      severity: Severity.HIGH,
      status: ThreatStatus.INVESTIGATING,
      sourceIp: internalIp(),
      destinationIp: '10.0.0.5',
      sourcePort: 50000,
      destinationPort: 88,
      protocol: 'Kerberos',
      detectionMethod: 'NETWORK_MONITORING',
      sourceSystem: 'FireEye',
      affectedHosts: 'DC-01.corp.local',
      affectedUsers: 'svc_sql, svc_backup, svc_exchange',
      mitreTactics: 'Credential Access',
      mitreTechniques: 'T1208',
      isAnomaly: true,
      anomalyScore: 0.87,
      confidence: 0.89,
      priority: 2,
      assignedToId: createdUsers[4].id, // dchen
    },
  ]

  const createdThreats = []
  const now = new Date()

  for (let i = 0; i < threatScenarios.length; i++) {
    const scenario = threatScenarios[i]
    const hoursAgo = i * 2 + Math.random() * 4
    const timestamp = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000)

    const threat = await prisma.threat.create({
      data: {
        ...scenario,
        timestamp,
        firstSeen: timestamp,
        lastSeen: new Date(timestamp.getTime() + Math.random() * 2 * 60 * 60 * 1000),
        incidentId: scenario.status === ThreatStatus.RESOLVED ? `INC-${2024001 + i}` : null,
      },
    })

    createdThreats.push(threat)
    console.log(`  Created threat ${i + 1}/${threatScenarios.length}: ${threat.title.substring(0, 50)}...`)

    // Create IOCs for each threat
    const iocTypes = [
      IOCType.IP_ADDRESS,
      IOCType.DOMAIN,
      IOCType.FILE_HASH_SHA256,
      IOCType.FILE_HASH_MD5,
      IOCType.URL,
      IOCType.PROCESS_NAME,
      IOCType.EMAIL,
    ]

    const iocCount = Math.floor(Math.random() * 3) + 2
    for (let j = 0; j < iocCount; j++) {
      const iocType = iocTypes[j % iocTypes.length]
      let iocValue = ''

      switch (iocType) {
        case IOCType.IP_ADDRESS:
          iocValue = scenario.sourceIp || scenario.destinationIp || externalIp()
          break
        case IOCType.DOMAIN:
          iocValue = `malicious${Math.floor(Math.random() * 10000)}.com`
          break
        case IOCType.FILE_HASH_SHA256:
          iocValue = hashGenerator('SHA256')
          break
        case IOCType.FILE_HASH_MD5:
          iocValue = hashGenerator('MD5')
          break
        case IOCType.URL:
          iocValue = `https://${Math.floor(Math.random() * 10000)}.com/payload.exe`
          break
        case IOCType.PROCESS_NAME:
          iocValue = ['svchost.exe', 'powershell.exe', 'explorer.exe', 'cmd.exe', 'wscript.exe', 'regsvr32.exe'][j % 6]
          break
        case IOCType.EMAIL:
          iocValue = `${scenario.affectedUsers?.split(',')[0] || 'user'}@${externalIp().split('.')[0]}.com`
          break
      }

      await prisma.iOC.create({
        data: {
          threatId: threat.id,
          type: iocType,
          value: iocValue,
          description: `${iocType} associated with ${scenario.title}`,
          confidence: 0.7 + Math.random() * 0.3,
          source: scenario.sourceSystem,
          firstSeen: timestamp,
          lastSeen: new Date(timestamp.getTime() + Math.random() * 60 * 60 * 1000),
          isActive: true,
        },
      })
    }

    // Create Timeline Events for each threat
    const eventTypes = ['STATUS_CHANGE', 'ASSIGNMENT', 'INVESTIGATION', 'ANALYSIS', 'CONTAINMENT', 'REMEDIATION']
    const eventCount = Math.floor(Math.random() * 3) + 1

    for (let k = 0; k < eventCount; k++) {
      const eventType = eventTypes[k % eventTypes.length]
      const eventTime = new Date(timestamp.getTime() + k * 30 * 60 * 1000)

      let description = ''
      switch (eventType) {
        case 'STATUS_CHANGE':
          description = `Threat status changed from DETECTED to ${threat.status}`
          break
        case 'ASSIGNMENT':
          description = `Threat assigned to ${createdUsers[Math.floor(Math.random() * createdUsers.length)].displayName}`
          break
        case 'INVESTIGATION':
          description = 'Initial investigation initiated by SOC team'
          break
        case 'ANALYSIS':
          description = 'Technical analysis completed. IOC extraction performed.'
          break
        case 'CONTAINMENT':
          description = 'Containment actions executed. Isolated affected hosts.'
          break
        case 'REMEDIATION':
          description = 'Remediation steps implemented. Systems patched.'
          break
      }

      await prisma.timelineEvent.create({
        data: {
          threatId: threat.id,
          eventType,
          eventTime,
          description,
          metadata: JSON.stringify({
            source: 'SOC Operations',
            analyst: createdUsers[Math.floor(Math.random() * createdUsers.length)].displayName,
          }),
          userId: createdUsers[Math.floor(Math.random() * createdUsers.length)].id,
          source: 'MANUAL',
        },
      })
    }

    // Create Security Events for baseline
    const securityEventCount = Math.floor(Math.random() * 5) + 2
    for (let m = 0; m < securityEventCount; m++) {
      const eventTime = new Date(timestamp.getTime() - Math.random() * 24 * 60 * 60 * 1000)

      await prisma.securityEvent.create({
        data: {
          eventType: ['LOGIN', 'NETWORK', 'PROCESS', 'FILE', 'REGISTRY'][m % 5],
          severity: [Severity.LOW, Severity.MEDIUM][Math.floor(Math.random() * 2)],
          timestamp: eventTime,
          sourceIp: scenario.sourceIp,
          destinationIp: scenario.destinationIp,
          sourceHost: scenario.affectedHosts?.split(',')[0],
          description: `Baseline security event related to ${scenario.title}`,
          isCorrelated: true,
          threatId: threat.id,
        },
      })
    }
  }

  console.log(`\n  Created ${createdThreats.length} threats with IOCs and timeline events`)

  // Create 30-day Analytics Data
  console.log('\nGenerating 30-day analytics data...')
  for (let day = 30; day >= 0; day--) {
    const date = new Date(now.getTime() - day * 24 * 60 * 60 * 1000)
    date.setHours(0, 0, 0, 0)

    const totalThreats = Math.floor(Math.random() * 15) + 5
    const criticalCount = Math.floor(Math.random() * 3)
    const highCount = Math.floor(Math.random() * 4) + 1
    const mediumCount = Math.floor(Math.random() * 5) + 2
    const lowCount = totalThreats - criticalCount - highCount - mediumCount

    await prisma.analyticsData.create({
      data: {
        date,
        totalThreats,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        resolvedCount: Math.floor(totalThreats * 0.85),
        falsePositiveCount: Math.floor(totalThreats * 0.13),
        anomalyCount: Math.floor(totalThreats * 0.4),
        mttr: 8 + Math.random() * 6,
        mttd: 3 + Math.random() * 4,
        uniqueIocs: Math.floor(totalThreats * 2.5),
      },
    })
  }
  console.log('  Generated 30 days of analytics data')

  // Create Sample Reports
  console.log('\nCreating sample reports...')
  const reports = [
    {
      reportNumber: 'RPT-2024-001',
      title: 'APT29 Supply Chain Attack - Initial Assessment',
      type: ReportType.APT_REPORT,
      description: 'Comprehensive analysis of APT29 supply chain attack affecting build systems and source code repositories. Includes attack timeline, IOCs, and containment actions.',
      severity: Severity.CRITICAL,
      status: 'PUBLISHED',
      createdBy: createdUsers[4].id, // dchen
      assignedTo: createdUsers[6].id, // rpatel
      startDate: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000),
      endDate: new Date(),
      executiveSummary: 'APT29 (Cozy Bear) launched a sophisticated supply chain attack targeting our build infrastructure. Attackers compromised the build pipeline, injected malicious code, and exfiltrated 15GB+ of source code and IP. Initial containment achieved. Full remediation in progress.',
      keyFindings: '1. Initial compromise via build server vulnerability\n2. Lateral movement to 8 systems\n3. IP theft including proprietary algorithms\n4. APT29 attribution with 92% confidence\n5. Supply chain affected for 14 days',
      recommendations: '1. Isolate compromised systems\n2. Rotate all credentials\n3. Review build pipeline security\n4. Implement code signing\n5. Enhance network segmentation',
      threatIds: createdThreats.slice(0, 8).map(t => t.id).join(','),
      isPublished: true,
      publishedAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    },
    {
      reportNumber: 'RPT-2024-002',
      title: 'Executive Spear Phishing Campaign - Weekly Summary',
      type: ReportType.PHISHING_REPORT,
      description: 'Summary of spear phishing campaign targeting C-level executives. Includes attack methodology, affected users, and preventive measures.',
      severity: Severity.HIGH,
      status: 'PUBLISHED',
      createdBy: createdUsers[5].id, // kmartinez
      assignedTo: createdUsers[1].id, // mjones
      startDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      endDate: new Date(),
      executiveSummary: 'Sophisticated spear phishing campaign targeting executive team. 15 phishing emails delivered, 3 accounts compromised. Attack showed high level of victim reconnaissance. BEC attempt for $150K successfully blocked.',
      keyFindings: '1. 15 targeted emails sent to executives\n2. 3 accounts compromised\n3. BEC attempt blocked\n4. Attackers used typo-squatted domains\n5. Social engineering sophistication: HIGH',
      recommendations: '1. Enhance email security controls\n2. Executive security awareness training\n3. Implement DMARC/DKIM/SPF\n4. Multi-factor authentication enforcement\n5. Outbound payment verification process',
      threatIds: createdThreats.slice(31, 37).map(t => t.id).join(','),
      isPublished: true,
      publishedAt: new Date(),
    },
  ]

  for (const report of reports) {
    await prisma.report.create({ data: report })
    console.log(`  Created report: ${report.title}`)
  }

  // Create Sample Hunting Queries
  console.log('\nCreating sample hunting queries...')
  const huntingQueries = [
    {
      name: 'Lateral Movement Detection',
      description: 'Detects lateral movement using SMB from non-admin workstations',
      query: 'SELECT * FROM network_events WHERE protocol="SMB" AND source_port>50000 AND destination_port=445 AND source_host NOT IN (SELECT hostname FROM admin_workstations)',
      filters: JSON.stringify({ timeRange: '7d', severity: ['HIGH', 'CRITICAL'] }),
      createdBy: createdUsers[4].id,
      isPublic: true,
      executionCount: 15,
      lastExecuted: new Date(Date.now() - 2 * 60 * 60 * 1000),
    },
    {
      name: 'PowerShell Anomaly Detection',
      description: 'Identifies anomalous PowerShell execution patterns',
      query: 'SELECT * FROM process_events WHERE process_name="powershell.exe" AND command_line LIKE "%EncodedCommand%" AND event_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)',
      filters: JSON.stringify({ timeRange: '24h', isAnomaly: 'true' }),
      createdBy: createdUsers[4].id,
      isPublic: true,
      executionCount: 23,
      lastExecuted: new Date(Date.now() - 1 * 60 * 60 * 1000),
    },
    {
      name: 'Data Exfiltration Large Files',
      description: 'Detects large file transfers to external IPs',
      query: 'SELECT * FROM network_events WHERE bytes_sent>100000000 AND destination_ip NOT IN (SELECT internal_network_ranges) AND time > DATE_SUB(NOW(), INTERVAL 24 HOUR)',
      filters: JSON.stringify({ timeRange: '24h', type: 'DATA_EXFILTRATION' }),
      createdBy: createdUsers[3].id, // slee
      isPublic: true,
      executionCount: 8,
      lastExecuted: new Date(Date.now() - 4 * 60 * 60 * 1000),
    },
  ]

  for (const query of huntingQueries) {
    await prisma.huntingQuery.create({ data: query })
  }
  console.log(`  Created ${huntingQueries.length} hunting queries`)

  console.log('\n✅ Enhanced seeding completed successfully!')
  console.log(`   - 8 Users (SOC team)`)
  console.log(`   - 5 Correlation Chains (including APT29, APT41)`)
  console.log(`   - ${createdThreats.length} Threats (diverse types including APT, Spear Phishing, Ransomware)`)
  console.log(`   - 30 days of Analytics Data`)
  console.log(`   - 2 Sample Reports`)
  console.log(`   - 3 Hunting Queries`)
}

main()
  .catch((e) => {
    console.error('Error seeding database:', e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
