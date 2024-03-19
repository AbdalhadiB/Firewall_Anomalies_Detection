# Firewall_Anomalies_Detection
Analyzing the firewall anomalies by Knowledge graph (Neo4j) 
1- Loading the dataset into the database of Neo4j:
LOAD CSV WITH HEADERS FROM 'file:///yozb_rtr_config.csv' AS row 
MERGE (m:line {Index: row.Index, Protocol: row.Protocol, SrcIP: row.SrcIP, DstIP: row.DstIP, SrcPort: row.SrcPort, DstPort: row.DstPort, Action: row.Action});

2- Preparing the database before applying the queries of the rules on it to generate the KG:
	1-MATCH (n) where n.DstPort CONTAINS "-" return DISTINCT n.DstPort
"631-636"
"901-1024"
"5556-5558"
"7000-7010"
"30001-65535"
"7000-7009"
"20-21"
"8070-8080"
"27001-65535"
"7226-7246"
"501-65535"
"140-65535"
"135-65535"
"161-162"
"135-139"
	MATCH (a) WHERE a.DstPort = "631-636" 
	SET a.DstPort = [631,636]
	RETURN a
	2-Casting the DstPort field to list[] type: 	
	MATCH (a) 
	SET a.DstPort = [a.DstPort]
	RETURN a
	3-Convert all numbers type string of the DstPort to integer by removing "" and change the name of the 	following  ports to numbers: 
	any==>0
	established==>1
	
3- Applying the queries of the rules on the database to generate the Kownlegde Graph:
	1.SHADOW CASE-1:
	MATCH (a), (b) WHERE a.Index < b.Index AND a.SrcIP = b.SrcIP AND a.DstIP = b.DstIP AND a.DstPort = 	b.DstPort AND a.Protocol = b.Protocol AND a.SrcPort = b.SrcPort AND a.Action <> b.Action CREATE (b)-[r: 	SHADOW_OF]->(a)  RETURN b,a 
	Result: 64 rel

	2.SHADOW CASE-2:
	MATCH (a), (b) WHERE a.Index < b.Index AND a.SrcIP = b.SrcIP AND a.SrcPort = b.SrcPort AND a.DstIP = 	b.DstIP AND a.DstPort = b.DstPort AND a.Action <> b.Action AND (a.Protocol="any" OR a.Protocol = 	b.Protocol) CREATE (b)-[r: SHADOW2_OF]->(a) RETURN a,b
	Result: 66 rel

	3.SHADOW CASE-3:
	MATCH (a), (b) WHERE a.Index < b.Index AND (a.SrcIP = "any" OR a.SrcIP = b.SrcIP) AND a.DstIP = b.DstIP 	AND a.SrcPort = b.SrcPort AND a.DstPort = b.DstPort AND a.Protocol = b.Protocol AND a.Action <> b.Action 	CREATE (b)-[r: SHADOW3_OF]->(a) RETURN b,a
	Result: 150 rel

	4.SHADOW CASE-4:
	MATCH (a), (b) WHERE a.Index < b.Index AND (a.DstIP = "any" OR a.DstIP = b.DstIP)  AND a.SrcIP = b.SrcIP 	AND a.SrcPort = b.SrcPort AND a.DstPort = b.DstPort AND a.Protocol = b.Protocol AND a.Action <> b.Action 	CREATE (b)-[r: SHADOW4_OF]->(a) RETURN b,a	
	Result: 588 rel

	5.SHADOW CASE-5:
	MATCH (a),(b) WHERE (b.DstPort[0] <= a.DstPort[1] AND b.DstPort[0] >= a.DstPort[0] OR a.DstPort[0] = 0) 	AND a.SrcIP = b.SrcIP 	AND a.DstIP = b.DstIP AND a.Protocol = b.Protocol AND a.SrcPort = b.SrcPort AND 	a.Action <> b.Action AND a.Index < b.Index  CREATE (b)-[r: SHADOW5_OF]->(a) RETURN a,b
	Result: 397 rel

	6.Correlation CASE-1:
	MATCH (a), (b) WHERE a.Index < b.Index AND a.SrcIP = b.SrcIP AND a.SrcPort = b.SrcPort AND a.DstIP = 	b.DstIP AND a.DstPort = b.DstPort AND a.Action <> b.Action AND (b.Protocol="any" OR a.Protocol = 	b.Protocol) CREATE (b)-[r: Correlation_1]->(a) RETURN a,b
	Result: 212 rel

	7.Correlation Case-2:
	MATCH (a), (b) WHERE a.Index < b.Index AND (b.SrcIP = "any" OR b.SrcIP = a.SrcIP) AND a.SrcPort = 	b.SrcPort AND a.DstIP = b.DstIP AND a.DstPort = b.DstPort AND a.Action <> b.Action AND a.Protocol = 	b.Protocol  CREATE (b)-[r: Correlation_2]->(a) RETURN a,b
	Result: 746 rel

	8.Correlation Case-3:
	MATCH (a), (b) WHERE a.Index < b.Index AND (b.DstIP = "any" OR a.DstIP = b.DstIP)  AND a.SrcIP = b.SrcIP 	AND a.SrcPort = b.SrcPort AND a.DstPort = b.DstPort AND a.Protocol = b.Protocol AND a.Action <> b.Action 	CREATE (b)-[r: Correlation_3]->(a) RETURN b,a
	Result: 1174 rel

	9.Generalization anomaly:
	The Correlation CASE-1,2,3 could be applied and satisfy the generalization anomaly.

	10.Irrelevant Case-1:
	MATCH (a) WHERE a.DstIP = a.SrcIP CREATE (a)-[r: Irrelation_1]->(a) RETURN a
	Result: 127 rel

	11.Irrelevant Case-2:
	MATCH (a) WHERE a.DstIP <> N/W OR a.DstPort <> N/W CREATE (a)-[r: Irrelation_2]->(a) RETURN a
	
	
	
	
