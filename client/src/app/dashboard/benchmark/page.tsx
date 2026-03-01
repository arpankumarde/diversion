"use client";

import React, { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart";
import {
  Bar,
  BarChart,
  XAxis,
  YAxis,
  Cell,
  PieChart,
  Pie,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from "recharts";

// ─── Static Data from juiceshop_vulnerabilities.json ───
const juiceShopData = {
  target: "OWASP Juice Shop",
  version: "v19.1.1",
  total_challenges: 110,
  source: "https://owasp.org/www-project-juice-shop/",
  categories: {
    "Sensitive Data Exposure": 15,
    "Improper Input Validation": 12,
    "Broken Access Control": 11,
    Injection: 11,
    "Broken Authentication": 9,
    "Vulnerable Components": 9,
    XSS: 9,
    Miscellaneous: 7,
    "Cryptographic Issues": 5,
    "Broken Anti Automation": 4,
    "Security Misconfiguration": 4,
    "Observability Failures": 4,
    "Insecure Deserialization": 3,
    "Security through Obscurity": 3,
    "Unvalidated Redirects": 2,
    XXE: 2,
  } as Record<string, number>,
  difficulty_distribution: {
    "1_star_trivial": 15,
    "2_star_easy": 20,
    "3_star_moderate": 30,
    "4_star_hard": 33,
    "5_star_very_hard": 28,
    "6_star_expert": 16,
  } as Record<string, number>,
};

// ─── Static Data from NAZITEST HTML Report ───
const scanMeta = {
  target: "https://juice.obvix.cloud",
  runId: "b7441a82_20260301_120530",
  generated: "2026-03-01T12:39:48+0530",
  tool: "NAZITEST v0.1.0",
  totalFindings: 103,
  graphNodes: 1247,
  critical: 19,
  high: 40,
  medium: 36,
  low: 8,
};

interface Vulnerability {
  title: string;
  type: string;
  endpoint: string;
  parameter: string;
  confidence: string;
  owasp: string;
  cwe: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

const vulnerabilities: Vulnerability[] = [
  { title: "SQL Injection in Login Endpoint via email parameter", type: "sqli", endpoint: "/rest/user/login", parameter: "email", confidence: "100%", owasp: "A03:2021 - Injection", cwe: "CWE-89", severity: "CRITICAL" },
  { title: "SQL Injection in Product Search via q parameter", type: "sqli", endpoint: "/rest/products/search", parameter: "q", confidence: "100%", owasp: "A03:2021 - Injection", cwe: "CWE-89", severity: "CRITICAL" },
  { title: "UNION-based SQLi - Dump User Credentials from Users Table", type: "sqli", endpoint: "/rest/products/search", parameter: "q", confidence: "100%", owasp: "A03:2021 - Injection", cwe: "CWE-89", severity: "CRITICAL" },
  { title: "SQL Injection - Extract Admin Password Hash via UNION SELECT", type: "sqli", endpoint: "/rest/products/search", parameter: "q", confidence: "100%", owasp: "A03:2021 - Injection", cwe: "CWE-89", severity: "CRITICAL" },
  { title: "SQL Injection - Extract TOTP Secrets to Bypass 2FA", type: "sqli", endpoint: "/rest/products/search", parameter: "q", confidence: "95%", owasp: "A03:2021 - Injection", cwe: "CWE-89", severity: "CRITICAL" },
  { title: "NoSQL Injection in Product Reviews via MongoDB operators", type: "nosqli", endpoint: "/rest/products/reviews", parameter: "id", confidence: "95%", owasp: "A03:2021 - Injection", cwe: "CWE-943", severity: "HIGH" },
  { title: "Server-Side Template Injection (SSTI) via username in profile", type: "ssti", endpoint: "/profile", parameter: "username", confidence: "100%", owasp: "A03:2021 - Injection", cwe: "CWE-94", severity: "CRITICAL" },
  { title: "SSTI RCE - Execute System Commands via eval() in username", type: "cmdi", endpoint: "/profile", parameter: "username", confidence: "100%", owasp: "A03:2021 - Injection", cwe: "CWE-94", severity: "CRITICAL" },
  { title: "SSTI RCE - Read Server-Side Files Including Database", type: "cmdi", endpoint: "/profile", parameter: "username", confidence: "100%", owasp: "A03:2021 - Injection", cwe: "CWE-94", severity: "CRITICAL" },
  { title: "Captcha Bypass via eval() Injection in captcha.ts", type: "cmdi", endpoint: "/api/Feedbacks", parameter: "captcha", confidence: "90%", owasp: "A03:2021 - Injection", cwe: "CWE-94", severity: "HIGH" },
  { title: "Log Injection via forged HTTP request headers", type: "log_injection", endpoint: "/rest/user/login", parameter: "X-Forwarded-For", confidence: "85%", owasp: "A03:2021 - Injection", cwe: "CWE-117", severity: "MEDIUM" },
  { title: "DOM XSS via Search Parameter q reflected in Angular template", type: "xss", endpoint: "/#/search", parameter: "q", confidence: "100%", owasp: "A03:2021 - Injection", cwe: "CWE-79", severity: "HIGH" },
  { title: "Reflected XSS via order tracking page id parameter", type: "xss", endpoint: "/#/track-result", parameter: "id", confidence: "95%", owasp: "A03:2021 - Injection", cwe: "CWE-79", severity: "HIGH" },
  { title: "Stored XSS via Product Review message field", type: "xss", endpoint: "/rest/products/1/reviews", parameter: "message", confidence: "90%", owasp: "A03:2021 - Injection", cwe: "CWE-79", severity: "HIGH" },
  { title: "Stored XSS via User Profile Username Field", type: "xss", endpoint: "/profile", parameter: "username", confidence: "92%", owasp: "A03:2021 - Injection", cwe: "CWE-79", severity: "HIGH" },
  { title: "XSS via Stored Review Author Field", type: "xss", endpoint: "/rest/products/reviews", parameter: "author", confidence: "85%", owasp: "A03:2021 - Injection", cwe: "CWE-79", severity: "MEDIUM" },
  { title: "Insecure CSP - unsafe-eval and unsafe-inline Enable XSS", type: "xss", endpoint: "/", parameter: "CSP Header", confidence: "90%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-1021", severity: "MEDIUM" },
  { title: "XSS via HTTP User-Agent in administration logs", type: "xss", endpoint: "/#/administration", parameter: "User-Agent", confidence: "80%", owasp: "A03:2021 - Injection", cwe: "CWE-79", severity: "MEDIUM" },
  { title: "DOM XSS via Angular template injection in product descriptions", type: "xss", endpoint: "/#/search", parameter: "product description", confidence: "88%", owasp: "A03:2021 - Injection", cwe: "CWE-79", severity: "HIGH" },
  { title: "Persistent XSS via support chat interface message", type: "xss", endpoint: "/#/chatbot", parameter: "message", confidence: "82%", owasp: "A03:2021 - Injection", cwe: "CWE-79", severity: "MEDIUM" },
  { title: "IDOR - Access Other Users' Baskets via basket ID manipulation", type: "idor", endpoint: "/rest/basket/1", parameter: "id", confidence: "100%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "HIGH" },
  { title: "IDOR - Add Items to Other Users' Baskets via BasketId", type: "idor", endpoint: "/api/BasketItems", parameter: "BasketId", confidence: "95%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "HIGH" },
  { title: "Admin User List Exposure Without Authorization Check", type: "idor", endpoint: "/rest/user/authentication-details", parameter: "", confidence: "100%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-284", severity: "HIGH" },
  { title: "IDOR - Access Other Users' Credit Cards via API", type: "idor", endpoint: "/api/Cards", parameter: "id", confidence: "92%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "HIGH" },
  { title: "IDOR - Delete Other Users' Basket Items", type: "idor", endpoint: "/api/BasketItems", parameter: "id", confidence: "88%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "MEDIUM" },
  { title: "Address ID Enumeration via Direct API Access", type: "idor", endpoint: "/api/Addresss", parameter: "id", confidence: "85%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "MEDIUM" },
  { title: "Order Tracking ID Exposure and Unauthorized Access", type: "idor", endpoint: "/rest/track-order", parameter: "id", confidence: "90%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "MEDIUM" },
  { title: "Recycles API IDOR - Access Other Users' Recycle History", type: "idor", endpoint: "/api/Recycles", parameter: "id", confidence: "82%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "MEDIUM" },
  { title: "Admin Application Configuration Exposed Without Auth", type: "idor", endpoint: "/rest/admin/application-configuration", parameter: "", confidence: "100%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-284", severity: "HIGH" },
  { title: "Forged Feedback - Submit Feedback as Another User", type: "idor", endpoint: "/api/Feedbacks", parameter: "UserId", confidence: "93%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "HIGH" },
  { title: "View Another User's Shopping Basket via Horizontal Privilege Escalation", type: "idor", endpoint: "/rest/basket", parameter: "id", confidence: "91%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-639", severity: "HIGH" },
  { title: "FTP Directory Listing Exposes Sensitive Files", type: "sensitive_data_exposure", endpoint: "/ftp", parameter: "", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-538", severity: "HIGH" },
  { title: "Encryption Keys Directory Publicly Accessible", type: "sensitive_data_exposure", endpoint: "/encryptionkeys", parameter: "", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-312", severity: "CRITICAL" },
  { title: "Support Logs Directory Contains Sensitive Information", type: "sensitive_data_exposure", endpoint: "/support/logs", parameter: "", confidence: "100%", owasp: "A09:2021 - Security Logging and Monitoring Failures", cwe: "CWE-532", severity: "HIGH" },
  { title: "JWT Token Leaked in Support Logs", type: "sensitive_data_exposure", endpoint: "/support/logs", parameter: "", confidence: "95%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-532", severity: "CRITICAL" },
  { title: "API Documentation Exposed at /api-docs", type: "sensitive_data_exposure", endpoint: "/api-docs", parameter: "", confidence: "100%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-200", severity: "MEDIUM" },
  { title: "Prometheus Metrics Endpoint Exposed", type: "sensitive_data_exposure", endpoint: "/metrics", parameter: "", confidence: "100%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-200", severity: "MEDIUM" },
  { title: "Coupon Codes Disclosed via FTP File Download", type: "sensitive_data_exposure", endpoint: "/ftp/coupons_2013.md.bak", parameter: "", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-312", severity: "HIGH" },
  { title: "KeePass Database Exposed via FTP Download", type: "sensitive_data_exposure", endpoint: "/ftp/incident-support.kdbx", parameter: "", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-312", severity: "CRITICAL" },
  { title: "Authentication Details Endpoint Exposes User Data", type: "sensitive_data_exposure", endpoint: "/rest/user/authentication-details", parameter: "", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-200", severity: "HIGH" },
  { title: "Exposed robots.txt Reveals Hidden Admin Paths", type: "sensitive_data_exposure", endpoint: "/robots.txt", parameter: "", confidence: "100%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-200", severity: "LOW" },
  { title: "Error Handling Reveals Stack Traces with Internal Paths", type: "sensitive_data_exposure", endpoint: "/rest/products/search", parameter: "q", confidence: "92%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-209", severity: "MEDIUM" },
  { title: "Confidential Document Access via Direct URL Guessing", type: "sensitive_data_exposure", endpoint: "/ftp/acquisitions.md", parameter: "", confidence: "95%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-538", severity: "HIGH" },
  { title: "Leaked Access Log Contains Session Tokens", type: "sensitive_data_exposure", endpoint: "/support/logs/access.log", parameter: "", confidence: "90%", owasp: "A09:2021 - Security Logging and Monitoring Failures", cwe: "CWE-532", severity: "HIGH" },
  { title: "Email Leaked in JWT Token Payload Without Encryption", type: "sensitive_data_exposure", endpoint: "/rest/user/login", parameter: "token", confidence: "95%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-312", severity: "MEDIUM" },
  { title: "Admin Password Hash Exposed in SQLi Response", type: "sensitive_data_exposure", endpoint: "/rest/products/search", parameter: "q", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-312", severity: "CRITICAL" },
  { title: "JWT Algorithm Confusion Attack - RS256 to HS256", type: "broken_auth", endpoint: "/rest/user/login", parameter: "Authorization", confidence: "100%", owasp: "A07:2021 - Identification and Authentication Failures", cwe: "CWE-345", severity: "CRITICAL" },
  { title: "JWT Forgery via Exposed RSA Public Key", type: "broken_auth", endpoint: "/encryptionkeys/jwt.pub", parameter: "Authorization", confidence: "100%", owasp: "A07:2021 - Identification and Authentication Failures", cwe: "CWE-345", severity: "CRITICAL" },
  { title: "Security Question Brute Force for Password Reset", type: "broken_auth", endpoint: "/rest/user/reset-password", parameter: "answer", confidence: "95%", owasp: "A07:2021 - Identification and Authentication Failures", cwe: "CWE-640", severity: "HIGH" },
  { title: "JWT Cookie Missing HttpOnly and Secure Flags", type: "broken_auth", endpoint: "/rest/user/login", parameter: "Set-Cookie", confidence: "100%", owasp: "A07:2021 - Identification and Authentication Failures", cwe: "CWE-614", severity: "MEDIUM" },
  { title: "Missing Rate Limiting on Login - Brute Force Possible", type: "broken_auth", endpoint: "/rest/user/login", parameter: "email,password", confidence: "92%", owasp: "A07:2021 - Identification and Authentication Failures", cwe: "CWE-307", severity: "HIGH" },
  { title: "Password Change via GET Request Without CSRF Token", type: "broken_auth", endpoint: "/rest/user/change-password", parameter: "current,new,repeat", confidence: "90%", owasp: "A07:2021 - Identification and Authentication Failures", cwe: "CWE-352", severity: "HIGH" },
  { title: "User Enumeration via Security Question Endpoint", type: "broken_auth", endpoint: "/rest/user/security-question", parameter: "email", confidence: "88%", owasp: "A07:2021 - Identification and Authentication Failures", cwe: "CWE-203", severity: "MEDIUM" },
  { title: "MD5 Password Hashing - Weak Cryptographic Algorithm", type: "broken_auth", endpoint: "/rest/user/login", parameter: "password", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-328", severity: "HIGH" },
  { title: "OAuth 2.0 Misconfiguration - Login via Manipulated Redirect", type: "broken_auth", endpoint: "/rest/user/login", parameter: "oauth", confidence: "85%", owasp: "A07:2021 - Identification and Authentication Failures", cwe: "CWE-601", severity: "HIGH" },
  { title: "Negative Quantity Basket Item Manipulation", type: "business_logic", endpoint: "/api/BasketItems", parameter: "quantity", confidence: "100%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-20", severity: "HIGH" },
  { title: "Wallet Balance Manipulation via Negative Amount", type: "business_logic", endpoint: "/api/Wallets", parameter: "amount", confidence: "95%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-20", severity: "HIGH" },
  { title: "Zero Star Rating Submission via API Manipulation", type: "business_logic", endpoint: "/api/Feedbacks", parameter: "rating", confidence: "92%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-20", severity: "MEDIUM" },
  { title: "Unrestricted File Upload - Upload Dangerous File Types", type: "business_logic", endpoint: "/file-upload", parameter: "file", confidence: "90%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-434", severity: "HIGH" },
  { title: "Mass Assignment - Modify User Role via Extra Parameters", type: "business_logic", endpoint: "/api/Users", parameter: "role", confidence: "88%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-915", severity: "CRITICAL" },
  { title: "Register User with Admin Role via Mass Assignment", type: "business_logic", endpoint: "/api/Users", parameter: "role", confidence: "92%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-915", severity: "CRITICAL" },
  { title: "Bypass Payment with Manipulated Total Price", type: "business_logic", endpoint: "/rest/basket/checkout", parameter: "totalPrice", confidence: "88%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-20", severity: "HIGH" },
  { title: "Bypass Quantity Limit via Race Condition in Cart", type: "business_logic", endpoint: "/api/BasketItems", parameter: "quantity", confidence: "82%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-362", severity: "HIGH" },
  { title: "Email Address Validation Bypass in Registration", type: "business_logic", endpoint: "/api/Users", parameter: "email", confidence: "90%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-20", severity: "MEDIUM" },
  { title: "Product Review Bypass - Review Without Purchase", type: "business_logic", endpoint: "/rest/products/1/reviews", parameter: "", confidence: "85%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-284", severity: "LOW" },
  { title: "Coupon Code Replay Attack - Apply Expired Coupons", type: "business_logic", endpoint: "/rest/basket/checkout", parameter: "couponCode", confidence: "92%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-20", severity: "HIGH" },
  { title: "Multiple Coupon Application via Race Condition", type: "business_logic", endpoint: "/rest/basket/checkout", parameter: "couponCode", confidence: "78%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-362", severity: "MEDIUM" },
  { title: "jQuery 2.2.4 with Known XSS CVEs", type: "vulnerable_component", endpoint: "/", parameter: "", confidence: "100%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-1104", severity: "MEDIUM" },
  { title: "Outdated Angular Framework with Known Vulnerabilities", type: "vulnerable_component", endpoint: "/", parameter: "", confidence: "95%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-1104", severity: "MEDIUM" },
  { title: "Express.js Version Disclosure via X-Powered-By Header", type: "vulnerable_component", endpoint: "/", parameter: "X-Powered-By", confidence: "100%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-200", severity: "LOW" },
  { title: "Vulnerable sanitize-html Package Allows XSS Bypass", type: "vulnerable_component", endpoint: "/api/Feedbacks", parameter: "comment", confidence: "90%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-1104", severity: "HIGH" },
  { title: "Outdated jsonwebtoken Library with JWT Bypass", type: "vulnerable_component", endpoint: "/rest/user/login", parameter: "", confidence: "88%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-1104", severity: "HIGH" },
  { title: "Outdated Sequelize ORM - SQL Injection Surface", type: "vulnerable_component", endpoint: "/", parameter: "", confidence: "85%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-1104", severity: "MEDIUM" },
  { title: "marsdb NoSQL Library with Injection Vulnerabilities", type: "vulnerable_component", endpoint: "/", parameter: "", confidence: "82%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-1104", severity: "MEDIUM" },
  { title: "Outdated Node.js Runtime with Known CVEs", type: "vulnerable_component", endpoint: "/", parameter: "", confidence: "80%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-1104", severity: "MEDIUM" },
  { title: "Legacy swagger-ui-express Exposes API Schema", type: "vulnerable_component", endpoint: "/api-docs", parameter: "", confidence: "88%", owasp: "A06:2021 - Vulnerable and Outdated Components", cwe: "CWE-1104", severity: "LOW" },
  { title: "Error Handling Reveals Application Stack Traces", type: "security_misconfig", endpoint: "/rest/products/search", parameter: "q", confidence: "100%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-209", severity: "MEDIUM" },
  { title: "Missing X-Frame-Options Header - Clickjacking", type: "security_misconfig", endpoint: "/", parameter: "", confidence: "90%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-1021", severity: "MEDIUM" },
  { title: "CORS Misconfiguration - Access-Control-Allow-Origin: *", type: "security_misconfig", endpoint: "/", parameter: "CORS", confidence: "100%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-942", severity: "MEDIUM" },
  { title: "Default Admin Credentials Not Changed", type: "security_misconfig", endpoint: "/rest/user/login", parameter: "email,password", confidence: "95%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-798", severity: "CRITICAL" },
  { title: "MD5 Used for Password Hashing - Easily Crackable", type: "crypto", endpoint: "/rest/user/login", parameter: "", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-328", severity: "HIGH" },
  { title: "Base64-Encoded Credentials in API Responses", type: "crypto", endpoint: "/rest/user/authentication-details", parameter: "", confidence: "92%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-261", severity: "MEDIUM" },
  { title: "Weak JWT Secret Susceptible to Brute Force", type: "crypto", endpoint: "/rest/user/login", parameter: "JWT", confidence: "88%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-326", severity: "HIGH" },
  { title: "RSA Public Key Exposed Enables JWT Forgery", type: "crypto", endpoint: "/encryptionkeys/jwt.pub", parameter: "", confidence: "100%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-321", severity: "CRITICAL" },
  { title: "Predictable Coupon Code Generation Algorithm", type: "crypto", endpoint: "/rest/basket/checkout", parameter: "couponCode", confidence: "82%", owasp: "A02:2021 - Cryptographic Failures", cwe: "CWE-330", severity: "MEDIUM" },
  { title: "Hidden Score Board Page Accessible via URL", type: "misc", endpoint: "/#/score-board", parameter: "", confidence: "100%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-200", severity: "LOW" },
  { title: "Privacy Policy Contains Hidden Functionality Hints", type: "misc", endpoint: "/#/privacy-security/privacy-policy", parameter: "", confidence: "90%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-200", severity: "LOW" },
  { title: "Blockchain-Related Easter Egg Endpoint", type: "misc", endpoint: "/#/blockchain", parameter: "", confidence: "85%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-200", severity: "LOW" },
  { title: "Premium Reward Feature Accessible Without Payment", type: "misc", endpoint: "/#/deluxe-membership", parameter: "", confidence: "82%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-284", severity: "MEDIUM" },
  { title: "Hidden Admin Section Accessible via Direct Navigation", type: "misc", endpoint: "/#/administration", parameter: "", confidence: "100%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-284", severity: "HIGH" },
  { title: "Chatbot Reveals Coupon Code via Social Engineering", type: "misc", endpoint: "/#/chatbot", parameter: "message", confidence: "88%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-200", severity: "MEDIUM" },
  { title: "Video Tutorial Contains Hidden Binary Easter Egg", type: "misc", endpoint: "/video", parameter: "", confidence: "78%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-200", severity: "LOW" },
  { title: "YAML Deserialization RCE in B2B Orders Endpoint", type: "deserialization", endpoint: "/b2b/v2/orders", parameter: "orderLinesData", confidence: "100%", owasp: "A08:2021 - Software and Data Integrity Failures", cwe: "CWE-502", severity: "CRITICAL" },
  { title: "Prototype Pollution via Lodash Merge in User Profile", type: "deserialization", endpoint: "/profile", parameter: "__proto__", confidence: "88%", owasp: "A08:2021 - Software and Data Integrity Failures", cwe: "CWE-1321", severity: "HIGH" },
  { title: "JSON.parse Injection via Crafted Order Payload", type: "deserialization", endpoint: "/api/Orders", parameter: "orderLines", confidence: "80%", owasp: "A08:2021 - Software and Data Integrity Failures", cwe: "CWE-502", severity: "MEDIUM" },
  { title: "CAPTCHA Bypass via Predictable Answer Pattern", type: "anti_automation", endpoint: "/api/Feedbacks", parameter: "captchaId", confidence: "92%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-804", severity: "MEDIUM" },
  { title: "No Rate Limiting on Password Reset Endpoint", type: "anti_automation", endpoint: "/rest/user/reset-password", parameter: "", confidence: "90%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-307", severity: "HIGH" },
  { title: "Automated Registration Without CAPTCHA", type: "anti_automation", endpoint: "/api/Users", parameter: "", confidence: "88%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-799", severity: "MEDIUM" },
  { title: "Mass Feedback Submission Without Throttling", type: "anti_automation", endpoint: "/api/Feedbacks", parameter: "", confidence: "85%", owasp: "A04:2021 - Insecure Design", cwe: "CWE-799", severity: "MEDIUM" },
  { title: "XXE Injection via File Upload Endpoint", type: "xxe", endpoint: "/file-upload", parameter: "file", confidence: "95%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-611", severity: "HIGH" },
  { title: "XXE via B2B Order XML Processing", type: "xxe", endpoint: "/b2b/v2/orders", parameter: "orderLinesData", confidence: "90%", owasp: "A05:2021 - Security Misconfiguration", cwe: "CWE-611", severity: "HIGH" },
  { title: "Open Redirect via /redirect endpoint allowlist bypass", type: "open_redirect", endpoint: "/redirect", parameter: "to", confidence: "100%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-601", severity: "MEDIUM" },
  { title: "Open Redirect via Manipulated OAuth Callback URL", type: "open_redirect", endpoint: "/rest/user/login", parameter: "oauth_redirect", confidence: "85%", owasp: "A01:2021 - Broken Access Control", cwe: "CWE-601", severity: "MEDIUM" },
];

// ─── Derived Data ───
const severityColors: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
};

const severityData = [
  { name: "Critical", value: scanMeta.critical, fill: "#dc2626" },
  { name: "High", value: scanMeta.high, fill: "#f97316" },
  { name: "Medium", value: scanMeta.medium, fill: "#eab308" },
  { name: "Low", value: scanMeta.low, fill: "#22c55e" },
];

// Group vulns by type
const typeGroups: Record<string, number> = {};
vulnerabilities.forEach((v) => {
  typeGroups[v.type] = (typeGroups[v.type] || 0) + 1;
});
const typeData = Object.entries(typeGroups)
  .sort((a, b) => b[1] - a[1])
  .map(([name, value]) => ({ name, value }));

const typeColors = [
  "#6366f1", "#8b5cf6", "#a855f7", "#d946ef", "#ec4899",
  "#f43f5e", "#ef4444", "#f97316", "#eab308", "#22c55e",
  "#14b8a6", "#06b6d4", "#3b82f6", "#2563eb",
];

// OWASP top-level grouping
const owaspGroups: Record<string, number> = {};
vulnerabilities.forEach((v) => {
  const key = v.owasp.split(" - ")[0];
  owaspGroups[key] = (owaspGroups[key] || 0) + 1;
});
const owaspData = Object.entries(owaspGroups)
  .sort((a, b) => b[1] - a[1])
  .map(([name, count]) => ({ name, count }));

// Difficulty data for chart
const difficultyData = Object.entries(juiceShopData.difficulty_distribution).map(
  ([key, val]) => ({
    name: key.replace(/_/g, " ").replace(/^\d+\s/, "★"),
    value: val,
  })
);

// Category data for chart
const categoryData = Object.entries(juiceShopData.categories)
  .sort((a, b) => b[1] - a[1])
  .map(([name, value]) => ({ name, value }));

// Benchmark radar: map NAZITEST types → Juice Shop categories
const benchmarkRadar = [
  { category: "Injection", juiceshop: 11, nazitest: vulnerabilities.filter(v => ["sqli", "nosqli", "ssti", "cmdi", "log_injection"].includes(v.type)).length },
  { category: "XSS", juiceshop: 9, nazitest: vulnerabilities.filter(v => v.type === "xss").length },
  { category: "Broken Access", juiceshop: 11, nazitest: vulnerabilities.filter(v => v.type === "idor").length },
  { category: "Data Exposure", juiceshop: 15, nazitest: vulnerabilities.filter(v => v.type === "sensitive_data_exposure").length },
  { category: "Auth Failures", juiceshop: 9, nazitest: vulnerabilities.filter(v => v.type === "broken_auth").length },
  { category: "Vuln Components", juiceshop: 9, nazitest: vulnerabilities.filter(v => v.type === "vulnerable_component").length },
  { category: "Misconfig", juiceshop: 4, nazitest: vulnerabilities.filter(v => v.type === "security_misconfig").length },
  { category: "Crypto", juiceshop: 5, nazitest: vulnerabilities.filter(v => v.type === "crypto").length },
  { category: "Deserialization", juiceshop: 3, nazitest: vulnerabilities.filter(v => v.type === "deserialization").length },
  { category: "Anti Automation", juiceshop: 4, nazitest: vulnerabilities.filter(v => v.type === "anti_automation").length },
  { category: "XXE", juiceshop: 2, nazitest: vulnerabilities.filter(v => v.type === "xxe").length },
  { category: "Redirects", juiceshop: 2, nazitest: vulnerabilities.filter(v => v.type === "open_redirect").length },
];

const chartConfig = {
  value: { label: "Count", color: "#6366f1" },
  count: { label: "Findings", color: "#8b5cf6" },
  nazitest: { label: "NAZITEST", color: "#6366f1" },
  juiceshop: { label: "Juice Shop", color: "#22c55e" },
};

type SeverityFilter = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export default function BenchmarkPage() {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const filteredVulns = vulnerabilities.filter((v) => {
    const matchSeverity = severityFilter === "ALL" || v.severity === severityFilter;
    const matchSearch =
      searchQuery === "" ||
      v.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.cwe.toLowerCase().includes(searchQuery.toLowerCase());
    return matchSeverity && matchSearch;
  });

  const detectionRate = Math.round(
    (scanMeta.totalFindings / juiceShopData.total_challenges) * 100
  );

  return (
    <div className="flex flex-col gap-6 p-4 md:p-6 w-full max-w-[1400px] mx-auto">
      {/* ── Header ── */}
      <div className="space-y-1">
        <h1 className="text-3xl font-bold tracking-tight">
          Benchmark Report
        </h1>
        <p className="text-muted-foreground">
          NAZITEST scan results benchmarked against OWASP Juice Shop {juiceShopData.version} <span className="text-foreground font-semibold">({juiceShopData.total_challenges} known challenges)</span>
        </p>
        <div className="flex flex-wrap gap-2 pt-2 text-xs text-muted-foreground">
          <span className="bg-muted px-2 py-0.5 rounded-md">Target: {scanMeta.target}</span>
          <span className="bg-muted px-2 py-0.5 rounded-md">Run: {scanMeta.runId}</span>
          <span className="bg-muted px-2 py-0.5 rounded-md">Date: {new Date(scanMeta.generated).toLocaleDateString()}</span>
          <span className="bg-muted px-2 py-0.5 rounded-md">{scanMeta.tool}</span>
        </div>
      </div>

      {/* ── Top Stats Row ── */}
      <div className="grid gap-4 grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
        <Card className="border-l-4 border-l-indigo-500">
          <CardContent className="pt-4 pb-3 px-4">
            <p className="text-xs text-muted-foreground font-medium">Total Findings</p>
            <p className="text-3xl font-bold mt-1">{scanMeta.totalFindings}</p>
          </CardContent>
        </Card>
        <Card className="border-l-4 border-l-red-500">
          <CardContent className="pt-4 pb-3 px-4">
            <p className="text-xs text-muted-foreground font-medium">Critical</p>
            <p className="text-3xl font-bold mt-1 text-red-500">{scanMeta.critical}</p>
          </CardContent>
        </Card>
        <Card className="border-l-4 border-l-orange-500">
          <CardContent className="pt-4 pb-3 px-4">
            <p className="text-xs text-muted-foreground font-medium">High</p>
            <p className="text-3xl font-bold mt-1 text-orange-500">{scanMeta.high}</p>
          </CardContent>
        </Card>
        <Card className="border-l-4 border-l-yellow-500">
          <CardContent className="pt-4 pb-3 px-4">
            <p className="text-xs text-muted-foreground font-medium">Medium</p>
            <p className="text-3xl font-bold mt-1 text-yellow-500">{scanMeta.medium}</p>
          </CardContent>
        </Card>
        <Card className="border-l-4 border-l-green-500">
          <CardContent className="pt-4 pb-3 px-4">
            <p className="text-xs text-muted-foreground font-medium">Low</p>
            <p className="text-3xl font-bold mt-1 text-green-500">{scanMeta.low}</p>
          </CardContent>
        </Card>
        <Card className="border-l-4 border-l-purple-500">
          <CardContent className="pt-4 pb-3 px-4">
            <p className="text-xs text-muted-foreground font-medium">Detection Rate</p>
            <p className="text-3xl font-bold mt-1 text-purple-500">{detectionRate}%</p>
          </CardContent>
        </Card>
      </div>

      {/* ── Charts Row 1: Severity Pie + Type Bar ── */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Severity Distribution Donut */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Severity Distribution</CardTitle>
            <CardDescription>Breakdown of {scanMeta.totalFindings} findings by severity level</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="mx-auto h-[280px]">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={3}
                  dataKey="value"
                  nameKey="name"
                  strokeWidth={2}
                  stroke="hsl(var(--background))"
                >
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <ChartTooltip content={<ChartTooltipContent />} />
              </PieChart>
            </ChartContainer>
            <div className="flex justify-center gap-4 -mt-2">
              {severityData.map((s) => (
                <div key={s.name} className="flex items-center gap-1.5 text-xs">
                  <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: s.fill }} />
                  <span className="text-muted-foreground">{s.name}</span>
                  <span className="font-semibold">{s.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Vulnerability Type Bar Chart */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Findings by Attack Type</CardTitle>
            <CardDescription>Distribution across {typeData.length} vulnerability categories</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="h-[300px]">
              <BarChart data={typeData} layout="vertical" margin={{ left: 10, right: 30 }}>
                <XAxis type="number" hide />
                <YAxis
                  dataKey="name"
                  type="category"
                  width={120}
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={14}>
                  {typeData.map((_, i) => (
                    <Cell key={i} fill={typeColors[i % typeColors.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      {/* ── Charts Row 2: Radar + OWASP ── */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Benchmark Radar */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Coverage Radar — NAZITEST vs Juice Shop</CardTitle>
            <CardDescription>
              Comparing detected vulnerabilities against known challenge categories
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="h-[320px]">
              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={benchmarkRadar}>
                <PolarGrid stroke="hsl(var(--border))" />
                <PolarAngleAxis dataKey="category" tick={{ fontSize: 10 }} />
                <PolarRadiusAxis angle={30} tick={{ fontSize: 9 }} />
                <Radar name="Juice Shop Challenges" dataKey="juiceshop" stroke="#22c55e" fill="#22c55e" fillOpacity={0.15} strokeWidth={2} />
                <Radar name="NAZITEST Findings" dataKey="nazitest" stroke="#6366f1" fill="#6366f1" fillOpacity={0.25} strokeWidth={2} />
                <ChartTooltip content={<ChartTooltipContent />} />
              </RadarChart>
            </ChartContainer>
            <div className="flex justify-center gap-6 -mt-2">
              <div className="flex items-center gap-1.5 text-xs">
                <div className="h-2.5 w-2.5 rounded-full bg-green-500" />
                <span className="text-muted-foreground">Juice Shop Challenges</span>
              </div>
              <div className="flex items-center gap-1.5 text-xs">
                <div className="h-2.5 w-2.5 rounded-full bg-indigo-500" />
                <span className="text-muted-foreground">NAZITEST Findings</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* OWASP Top 10 Bar */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">OWASP 2021 Top 10 Mapping</CardTitle>
            <CardDescription>Findings mapped to OWASP risk categories</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="h-[320px]">
              <BarChart data={owaspData} layout="vertical" margin={{ left: 0, right: 30 }}>
                <XAxis type="number" hide />
                <YAxis
                  dataKey="name"
                  type="category"
                  width={60}
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={18}>
                  {owaspData.map((_, i) => (
                    <Cell key={i} fill={i < 3 ? "#dc2626" : i < 6 ? "#f97316" : "#6366f1"} />
                  ))}
                </Bar>
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      {/* ── Juice Shop Benchmark Section ── */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Difficulty Distribution */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Juice Shop Challenge Difficulties</CardTitle>
            <CardDescription>
              Target vulnerability complexity — Total: {juiceShopData.total_challenges}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(juiceShopData.difficulty_distribution).map(([key, val]) => {
                const maxVal = Math.max(...Object.values(juiceShopData.difficulty_distribution));
                return (
                  <div key={key} className="flex items-center gap-3">
                    <span className="text-xs font-medium capitalize w-28 text-muted-foreground">
                      {key.replace(/_/g, " ")}
                    </span>
                    <div className="flex-1 bg-secondary rounded-full h-2">
                      <div
                        className="bg-gradient-to-r from-indigo-500 to-purple-500 h-2 rounded-full transition-all duration-700"
                        style={{ width: `${(val / maxVal) * 100}%` }}
                      />
                    </div>
                    <span className="text-xs font-bold w-6 text-right">{val}</span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Category Distribution */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Juice Shop Category Breakdown</CardTitle>
            <CardDescription>Known vulnerability categories in the benchmark target</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="h-[300px]">
              <BarChart data={categoryData} layout="vertical" margin={{ left: 10, right: 20 }}>
                <XAxis type="number" hide />
                <YAxis
                  dataKey="name"
                  type="category"
                  width={160}
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={12} fill="#8b5cf6" />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      {/* ── Vulnerability List ── */}
      {/* <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <CardTitle className="text-base">Discovered Vulnerabilities</CardTitle>
              <CardDescription>
                Showing {filteredVulns.length} of {vulnerabilities.length} findings from NAZITEST scan
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                placeholder="Search vulns..."
                className="px-3 py-1.5 text-sm rounded-md border bg-background w-48"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as SeverityFilter[]).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md border transition-colors ${severityFilter === sev
                    ? "bg-primary text-primary-foreground"
                    : "bg-background hover:bg-muted"
                    }`}
                >
                  {sev === "ALL" ? `All (${vulnerabilities.length})` : `${sev} (${vulnerabilities.filter((v) => v.severity === sev).length})`}
                </button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px] pr-4">
            <div className="space-y-3">
              {filteredVulns.map((v, i) => (
                <div
                  key={i}
                  className="flex flex-col gap-1.5 p-3 rounded-lg border hover:bg-muted/50 transition-colors"
                  style={{ borderLeftWidth: 3, borderLeftColor: severityColors[v.severity] }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-sm font-semibold leading-snug">{v.title}</span>
                    <Badge
                      variant={
                        v.severity === "CRITICAL"
                          ? "destructive"
                          : v.severity === "HIGH"
                            ? "default"
                            : "secondary"
                      }
                      className={`shrink-0 ${v.severity === "MEDIUM"
                        ? "bg-yellow-500 hover:bg-yellow-600 text-white"
                        : v.severity === "LOW"
                          ? "bg-green-500 hover:bg-green-600 text-white"
                          : ""
                        }`}
                    >
                      {v.severity}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <span className="uppercase tracking-wider font-medium">{v.type}</span>
                    <span>
                      <span className="font-medium text-foreground/60">Endpoint:</span>{" "}
                      <code className="text-[11px] bg-muted px-1 py-0.5 rounded">{v.endpoint}</code>
                    </span>
                    {v.parameter && (
                      <span>
                        <span className="font-medium text-foreground/60">Param:</span>{" "}
                        <code className="text-[11px] bg-muted px-1 py-0.5 rounded">{v.parameter}</code>
                      </span>
                    )}
                    <span>
                      <span className="font-medium text-foreground/60">Confidence:</span> {v.confidence}
                    </span>
                    <span className="text-[11px]">{v.owasp}</span>
                    <span className="text-[11px] font-mono">{v.cwe}</span>
                  </div>
                </div>
              ))}
              {filteredVulns.length === 0 && (
                <div className="text-center py-12 text-muted-foreground">
                  No vulnerabilities match the current filters.
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card> */}

      {/* ── Footer ── */}
      <div className="text-center text-xs text-muted-foreground pb-4">
        Generated by {scanMeta.tool} • {scanMeta.graphNodes} graph nodes explored • Benchmarked against {juiceShopData.target} {juiceShopData.version}
      </div>
    </div>
  );
}
