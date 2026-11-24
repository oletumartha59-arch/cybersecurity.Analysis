CREATE DATABASE C_SERCURITY_DB; 
USE C_SERCURITY_DB;

-- How many organizations are in the dataset /*
SELECT COUNT(*) AS total_organizations
FROM organizations;

-- TOTAL LOGIN /*
SELECT COUNT(distinct login_id) AS total_login_logs
FROM login_logs;

-- TOTAL INCIDENT /*
SELECT COUNT(INCIDENT_ID) AS TOTAL_INCIDENT
FROM SECURITY_INCIDENTS;

-- TOTAL NUMBER OF USERS /*
SELECT COUNT(distinct user_id) AS total_users
FROM Users;

-- NUMBER OF TIMES EACH USERS LOG IN /*
SELECT USER_ID, COUNT(LOGIN_ID)AS TOTAL_LOGIN_PER_USERS
FROM LOGIN_LOGS
GROUP BY USER_ID
ORDER BY TOTAL_LOGIN_PER_USERS DESC;

-- Which industries appear most frequently? /*
SELECT industry, COUNT(*) AS industry_count
FROM organizations
GROUP BY industry
ORDER BY industry_count DESC;

-- WHAT IS THE TOTAL NUMBER THAT OCCUR FOR EACH INCIDENT TYPE /*
SELECT INCIDENT_TYPE, COUNT(INCIDENT_ID) AS TOTAL_COUNT_PER_INCIDENT_TYPE
FROM SECURITY_INCIDENTS
GROUP BY INCIDENT_TYPE
ORDER BY TOTAL_COUNT_PER_INCIDENT_TYPE DESC;

-- Which operating systems are most common? /*
SELECT os_type, COUNT(*) AS total_systems
FROM systems
GROUP BY os_type
ORDER BY total_systems DESC;

-- Which users have the most failed login attempts? /*
SELECT user_id, COUNT(*) AS failed_attempts
FROM login_logs
WHERE status = 'failed'
GROUP BY user_id
ORDER BY failed_attempts DESC;

-- Which systems generate the most security events? /*
SELECT system_id, COUNT(*) AS event_count
FROM network_events
GROUP BY system_id
ORDER BY event_count DESC;

-- Which organizations have the most incidents? /*
SELECT org_id, COUNT(*) AS total_incidents
FROM security_incidents
GROUP BY org_id
ORDER BY total_incidents DESC;

-- Which systems are involved in the most incidents? /*
SELECT system_id, COUNT(*) AS incident_count
FROM incident_systems
GROUP BY system_id
ORDER BY incident_count DESC;

-- Detect suspicious login patterns by IP address /*
SELECT ip_address, COUNT(*) AS failed_attempts
FROM login_logs
WHERE status = 'failed'
GROUP BY ip_address
HAVING COUNT(*) > 0
ORDER BY failed_attempts DESC;

-- Identify users with abnormal login frequency /*
SELECT user_id, COUNT(*) AS login_count
FROM login_logs
GROUP BY user_id
HAVING COUNT(*) > (
    SELECT AVG(login_total)
    FROM (
        SELECT COUNT(*) AS login_total
        FROM login_logs
        GROUP BY user_id
    ) AS avg_logins
);


-- Find systems generating critical alerts /*
SELECT system_id, COUNT(*) AS critical_events
FROM network_events
WHERE severity = 'critical'
GROUP BY system_id
ORDER BY critical_events DESC;

-- Find industries with highest security incidents /*
SELECT o.industry, COUNT(si.incident_id) AS total_incidents
FROM organizations o
JOIN security_incidents si
ON o.org_id = si.org_id
GROUP BY o.industry
ORDER BY total_incidents DESC;

-- Calculate incident frequency by month /*
SELECT DATE_FORMAT(discovered_date, '%Y-%m') AS incident_month,
COUNT(*) AS incident_count
FROM security_incidents
GROUP BY incident_month
ORDER BY incident_month;

-- Calculate incident frequency by Year /*
SELECT YEAR(discovered_date) AS incident_year,
COUNT(*) AS incident_count
FROM security_incidents
GROUP BY incident_year
ORDER BY incident_year;

-- Identify organizations with highest risk /*
SELECT o.org_id, o.industry, COUNT(si.incident_id) AS total_incidents
FROM organizations o
JOIN security_incidents si
ON o.org_id = si.org_id
GROUP BY o.org_id, o.industry
ORDER BY total_incidents DESC;

SELECT o.org_id, si.incident_type, COUNT(si.incident_id) AS total_incidents
FROM organizations o
JOIN security_incidents si
ON o.org_id = si.org_id
GROUP BY o.org_id, si.incident_type
ORDER BY total_incidents DESC;

SELECT * FROM ORGANIZATIONS;

SELECT * FROM USERS;

SELECT * FROM SYSTEMS;

SELECT * FROM SECURITY_INCIDENTS;

SELECT * FROM LOGIN_LOGS;

SELECT * FROM NETWORK_EVENTS;

SELECT * FROM INCIDENT_SYSTEMS;

