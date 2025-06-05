using System;
using System.Data.SqlClient;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Xml;
using System.Runtime.Serialization.Formatters.Binary;
using System.DirectoryServices;
using System.Diagnostics;

namespace VulnerableTestApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("SAST Test Application Started");
            
            var testCases = new VulnerabilityTestCases();
            
            // Only call live vulnerabilities - others are dead code
            testCases.MustFixSqlInjection("user123");
            testCases.GoodToFixWeakCrypto("password123");
            testCases.FalsePositiveSanitizedXSS("<script>alert('xss')</script>");
            testCases.FalsePositiveProtectedFileAccess("../../../etc/passwd");
            
            Console.WriteLine("Application completed");
        }
    }

    public class VulnerabilityTestCases
    {
        private readonly string connectionString = "Server=localhost;Database=TestDB;Integrated Security=true;";

        // ========== CATEGORY 1: FALSE_POSITIVE_DEAD_CODE ==========
        // These methods contain vulnerabilities but are never called (dead code)
        
        [Obsolete("This method is deprecated and unused", true)]
        private void DeadCodeSqlInjection(string userInput)
        {
            // DEAD CODE - SQL Injection that Semgrep would detect
            string query = "SELECT * FROM Users WHERE name = '" + userInput + "'";
            using (var connection = new SqlConnection(connectionString))
            {
                var command = new SqlCommand(query, connection);
                connection.Open();
                command.ExecuteReader();
            }
        }

        private void UnusedPathTraversal(string fileName)
        {
            // DEAD CODE - Path traversal that Semgrep detects
            string filePath = "/app/files/" + fileName;
            File.ReadAllText(filePath);
        }

        private void DeadXSSMethod(string userContent)
        {
            // DEAD CODE - XSS vulnerability in dead method
            string html = "<div>" + userContent + "</div>";
            Console.WriteLine(html);
        }

        private void UnusedCommandInjection(string userInput)
        {
            // DEAD CODE - Command injection
            Process.Start("cmd.exe", "/c " + userInput);
        }

        private void DeadLdapInjection(string username)
        {
            // DEAD CODE - LDAP injection
            DirectoryEntry entry = new DirectoryEntry();
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = "(&(objectClass=user)(cn=" + username + "))";
            searcher.FindAll();
        }

        private void UnusedXxeVulnerability(string xmlContent)
        {
            // DEAD CODE - XXE vulnerability
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlContent);
        }

        private void DeadWeakCrypto(string data)
        {
            // DEAD CODE - Weak cryptography
            MD5 md5Hash = MD5.Create();
            byte[] hash = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        // Unreachable code after return
        private void UnreachableVulnerabilities(string input)
        {
            Console.WriteLine("This executes");
            return;
            
            // DEAD CODE - Unreachable after return
            string sql = "DELETE FROM Users WHERE id = " + input;
            using (var connection = new SqlConnection(connectionString))
            {
                var command = new SqlCommand(sql, connection);
                connection.Open();
                command.ExecuteNonQuery();
            }
        }

        // Conditional dead code
        private void ConditionalDeadCode()
        {
            const bool ENABLE_DEBUG = false;
            
            if (ENABLE_DEBUG) // Always false
            {
                // DEAD CODE - Hardcoded credentials
                string password = "admin123";
                string connectionStr = "Server=prod;Database=main;User=admin;Password=" + password + ";";
                
                // DEAD CODE - SQL injection in dead branch
                string query = "SELECT * FROM admin WHERE pass = '" + password + "'";
            }
        }

        // ========== CATEGORY 2: FALSE_POSITIVE_SANITIZED ==========
        // Vulnerabilities that are properly sanitized
        
        public void FalsePositiveSanitizedXSS(string userInput)
        {
            // Semgrep may flag string concatenation, but it's sanitized
            string sanitized = HttpUtility.HtmlEncode(userInput);
            string output = "<div>" + sanitized + "</div>";
            Console.WriteLine(output);
        }

        public void FalsePositiveSanitizedSql(string userId)
        {
            // Using parameterized queries (properly sanitized)
            string query = "SELECT * FROM Users WHERE id = @userId";
            using (var connection = new SqlConnection(connectionString))
            {
                var command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@userId", userId);
                connection.Open();
                command.ExecuteReader();
            }
        }

        public void FalsePositiveSanitizedPath(string fileName)
        {
            // Path is sanitized before use
            string sanitized = Path.GetFileName(fileName); // Removes path traversal
            string safePath = Path.Combine(@"C:\SafeUploads\", sanitized);
            
            if (File.Exists(safePath))
            {
                File.ReadAllText(safePath);
            }
        }

        public void FalsePositiveSanitizedLdap(string username)
        {
            // LDAP query with proper escaping
            string escapedUsername = username.Replace("(", "\\28").Replace(")", "\\29").Replace("*", "\\2A");
            DirectoryEntry entry = new DirectoryEntry();
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = "(&(objectClass=user)(cn=" + escapedUsername + "))";
            searcher.FindAll();
        }

        // ========== CATEGORY 3: FALSE_POSITIVE_PROTECTED ==========
        // Vulnerabilities protected by strong controls
        
        public void FalsePositiveProtectedFileAccess(string filePath)
        {
            // Strong authorization and validation
            if (!IsAdminUser() || !IsValidPath(filePath))
            {
                throw new UnauthorizedAccessException();
            }

            // Even though path concatenation looks vulnerable, controls protect it
            string fullPath = @"C:\SecureData\" + Path.GetFileName(filePath);
            if (File.Exists(fullPath) && IsInAllowedDirectory(fullPath))
            {
                File.ReadAllText(fullPath);
            }
        }

        public void FalsePositiveProtectedSql(string searchTerm)
        {
            // Multiple layers of protection
            if (!IsAuthenticated() || searchTerm.Length > 20 || ContainsSqlChars(searchTerm))
            {
                throw new ArgumentException("Invalid input");
            }

            // Limited to read-only, non-sensitive data with input restrictions
            string query = "SELECT title FROM PublicArticles WHERE title LIKE '%" + searchTerm + "%'";
            using (var connection = new SqlConnection(connectionString))
            {
                var command = new SqlCommand(query, connection);
                connection.Open();
                command.ExecuteReader(); // Read-only operation on public data
            }
        }

        // ========== CATEGORY 4: MUST_FIX ==========
        // Critical vulnerabilities that must be fixed
        
        public void MustFixSqlInjection(string userInput)
        {
            // CRITICAL: Direct SQL injection - Semgrep will definitely detect this
            string query = "SELECT * FROM Users WHERE username = '" + userInput + "' AND role = 'admin'";
            using (var connection = new SqlConnection(connectionString))
            {
                var command = new SqlCommand(query, connection);
                connection.Open();
                var result = command.ExecuteReader();
                
                if (result.HasRows)
                {
                    GrantAdminAccess();
                }
            }
        }

        public void MustFixPathTraversal(string fileName)
        {
            // CRITICAL: Direct path traversal
            string filePath = @"C:\WebRoot\uploads\" + fileName;
            string content = File.ReadAllText(filePath);
            Console.WriteLine(content);
        }

        public void MustFixCommandInjection(string command)
        {
            // CRITICAL: Command injection
            Process.Start("powershell.exe", "-Command " + command);
        }

        public void MustFixLdapInjection(string userInput)
        {
            // CRITICAL: LDAP injection
            DirectoryEntry entry = new DirectoryEntry();
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = "(&(objectClass=user)(uid=" + userInput + "))";
            SearchResultCollection results = searcher.FindAll();
        }

        public void MustFixXxeVulnerability(string xmlInput)
        {
            // CRITICAL: XXE vulnerability
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlInput); // Allows external entities
        }

        // ========== CATEGORY 5: GOOD_TO_FIX ==========
        // Medium risk vulnerabilities
        
        public void GoodToFixWeakCrypto(string password)
        {
            // MEDIUM: Weak cryptography - MD5
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                string hashString = Convert.ToBase64String(hash);
                Console.WriteLine("Hash: " + hashString);
            }
        }

        public void GoodToFixWeakRandomness()
        {
            // MEDIUM: Weak random number generation
            Random rand = new Random();
            string sessionId = rand.Next().ToString();
            Console.WriteLine("Session ID: " + sessionId);
        }

        public void GoodToFixInformationDisclosure(string fileName)
        {
            // MEDIUM: Information disclosure in error messages
            try
            {
                File.ReadAllText(fileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error accessing file: " + ex.Message + " at " + ex.StackTrace);
            }
        }

        public void GoodToFixInsecureDeserialization(byte[] data)
        {
            // MEDIUM: Insecure deserialization
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream stream = new MemoryStream(data))
            {
                object obj = formatter.Deserialize(stream);
            }
        }

        public void GoodToFixWeakCertificateValidation()
        {
            // MEDIUM: Weak certificate validation
            var client = new HttpClient();
            System.Net.ServicePointManager.ServerCertificateValidationCallback = 
                (sender, certificate, chain, sslPolicyErrors) => true; // Always accept
        }

        // ========== HELPER METHODS ==========
        
        private bool IsAdminUser() => true;
        private bool IsValidPath(string path) => !path.Contains("..");
        private bool IsAuthenticated() => true;
        private bool IsInAllowedDirectory(string path) => true;
        private bool ContainsSqlChars(string input) => 
            input.Contains("'") || input.Contains(";") || input.Contains("--");
        private void GrantAdminAccess() => Console.WriteLine("Admin access granted");
    }

    // ========== DEAD CODE CLASSES ==========
    
    [Obsolete("Legacy authentication class - no longer used", true)]
    public class DeadLegacyAuth
    {
        // DEAD CODE - Entire class is obsolete and contains vulnerabilities
        public bool AuthenticateUser(string username, string password)
        {
            // SQL injection in dead code
            string query = "SELECT COUNT(*) FROM Users WHERE username='" + username + 
                          "' AND password='" + password + "'";
            return true;
        }

        public void LogUserAccess(string userAgent)
        {
            // Log injection in dead code
            string logEntry = "User accessed system: " + userAgent;
            File.AppendAllText(@"C:\logs\access.log", logEntry);
        }
    }

    internal class UnusedUtilityClass
    {
        // DEAD CODE - Never instantiated or called
        public static void ProcessXmlFile(string xmlContent)
        {
            // XXE in dead code
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlContent);
        }

        public static void ExecuteSystemCommand(string cmd)
        {
            // Command injection in dead code
            Process.Start("cmd.exe", "/c " + cmd);
        }

        public static string HashPassword(string password)
        {
            // Weak crypto in dead code
            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hash);
            }
        }
    }

#if DEBUG && NEVER_DEFINED
    // DEAD CODE - Conditional compilation that never triggers
    public class ConditionalDeadCode
    {
        public void ProcessUserData(string data)
        {
            // SQL injection in conditional dead code
            string sql = "INSERT INTO UserData VALUES ('" + data + "')";
            
            // Hardcoded credentials in dead code
            string connStr = "Server=prod;User=admin;Password=P@ssw0rd123;";
        }
    }
#endif
}
