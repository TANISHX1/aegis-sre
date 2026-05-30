import sys
import os
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.coral_executor import execute_coral_query

def run_tests():
    print("========================================")
    print("AEGIS-SRE: RUNNING INTEGRATION TESTS")
    print("========================================\n")
    
    repo_owner = "Harshit7623"
    repo_name = "Aegis_demo_repo"
    
    # TEST 1: GitHub Commit Scan
    print("=== TEST 1: GitHub Commit Scan ===")
    query1 = f"""
    SELECT sha, commit__author__name, commit__message 
    FROM github.commits 
    WHERE owner = '{repo_owner}' AND repo = '{repo_name}' 
    LIMIT 3
    """
    print(f"Executing: {query1.strip()}")
    result1 = execute_coral_query(query1)
    print(f"Status: {result1.get('status')}")
    print(json.dumps(result1.get('data', [])[:2], indent=2))
    print("\n")
    
    # TEST 2: Normal Log Vulnerability Scan (OSV + Logs)
    print("=== TEST 2: Local Logs + OSV Vulnerability Scan ===")
    query2 = """
    WITH all_logs AS (
        SELECT timestamp, service, message, response_code FROM local_file.api_gateway_logs
        UNION ALL
        SELECT timestamp, service, message, response_code FROM local_file.auth_service_logs
        UNION ALL
        SELECT timestamp, service, message, response_code FROM local_file.payment_gateway_logs
    )
    SELECT l.timestamp, l.service, l.message, o.package_name, o.cve, o.severity
    FROM all_logs l
    JOIN osv.packages o ON l.message LIKE CONCAT('%', o.package_name, '%')
    WHERE l.response_code >= 500
    ORDER BY l.service
    LIMIT 10
    """
    print(f"Executing: {query2.strip()}")
    result2 = execute_coral_query(query2)
    print(f"Status: {result2.get('status')}")
    print(json.dumps(result2.get('data', []), indent=2))
    print("\n")
    
    # TEST 3: The 3-Way Integrated Checkup Join (Logs + OSV + GitHub)
    print("=== TEST 3: The 3-Way Integrated Checkup Join ===")
    query3 = f"""
    WITH all_logs AS (
        SELECT timestamp, service, message, response_code FROM local_file.api_gateway_logs
        UNION ALL
        SELECT timestamp, service, message, response_code FROM local_file.auth_service_logs
        UNION ALL
        SELECT timestamp, service, message, response_code FROM local_file.payment_gateway_logs
    )
    SELECT 
        l.service, l.response_code,
        o.package_name, o.cve, o.severity,
        g.sha, g.commit__author__name, g.commit__message
    FROM all_logs l
    JOIN osv.packages o ON l.message LIKE CONCAT('%', o.package_name, '%')
    JOIN github.commits g ON g.commit__message LIKE CONCAT('%', o.package_name, '%')
    WHERE g.owner = '{repo_owner}' AND g.repo = '{repo_name}' 
      AND l.response_code >= 500
    ORDER BY l.service
    LIMIT 10
    """
    print(f"Executing: {query3.strip()}")
    result3 = execute_coral_query(query3)
    print(f"Status: {result3.get('status')}")
    print(json.dumps(result3.get('data', []), indent=2))
    print("\n")

if __name__ == "__main__":
    run_tests()
