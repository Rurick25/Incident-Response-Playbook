# Introduction
  Purpose of this playbook
  Scope: Defining the types of DDoS attacks (Voumetric, Protocl, application layer)
  Target Audience: This playbook is for potential employers, SOC analysts and IT staff

### Roles and Responsibilities
  Incident Repsonse team:
    - Team lead: Overall coordinator 
    - Network Engineer: Handles network related issues
    - Security Analyst: Monitors and investigates alerts
    - Communication Lead: Manages internal and external communication

### DDoS Attack Indicators
 #### Symptoms: 
    - Unusual traffic patterns: 
    - Service availabiltiy issues (500/503 errors):
    - High CPU-memory usage: 

  ### Monitoring Tools:
    - Netflow
    - sFlow
    - Intrusion Detection Systems (IDS)

## Step by Step

  ### Detection
   #### Tools and alerts:
      - Set up alerts for unusual traffic spikes
      - Use inline Packet Inspection and Traffic Flow Analysis
  #### Actions to take:
      - Confirm the attack using logs and monitoring dashboards
      - Notify the IRT (Incident Response team)
      
  ### Analysis
   #### Traffic Analysis 
      - Identify the type of DDOS attack
      - Examine traffic sources and patterns
   #### Tools
      Utilize Wireshark, MISP, and AIL for deeper insight
      
  ### Containment
  #### Immediate Actions
      - Implement rate limiting on routers and firewalls
      - Block malicious IPs using ACLs
  #### Mitigation Tools
      - Activate DDoS protection services like cloudflare, AWS Shield, or similar. 
      
 ### Eradication
   #### Actions
      - Remove IP blocks that are no longer neccesary
      - Patch exploited vulnerabilities
   #### Tools
      - Ensure DNS servers are secured and services patched
      
  ### Recovery
   #### Service Restoration
      - Gradually restore services starting with critical components
      - Monitor traffic to ensure stability
   #### Verification
      - Conduct load tests to confirm service capacity
      
  ### Review and Document
  #### Post-Incident Analysis 
      - Hold a meeting a review response effectiveness
      - Document the incident details and lessons learned
  #### Update Playbook 
      - Incorporate any neccesary changes to the response strategy
      
  Communication Plan
  Tools and Resources
