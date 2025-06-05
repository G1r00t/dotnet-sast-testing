using System;
using System.Data.SqlClient;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace VulnerableTestApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("SAST Test Application Started");
            
            var testCases = new VulnerabilityTestCases();
            
            // Only call live vulnerabilities
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
        // These methods are never called and represent dead code
        
        [Obsolete("This method is deprecated and unused", true)]
        private void DeadCodeSqlInjection1(string userInput)
        {
            // DEAD CODE - This method is never called
            using (var connection = new SqlConnection(connectionString))
            {
                var query = $"SELECT * FROM Users WHERE username = '{userInput}'";
                var command = new SqlCommand(query, connection);
                connection.Open();
                command.ExecuteReader();
            }
        }

        private void UnusedVulnerableMethod(string filePath)
        {
            // DEAD CODE - This method is never referenced anywhere
            File.ReadAllText(filePath); // Path traversal vulnerability but dead code
        }

        private string DeadCodeXSSVulnerability(string userContent)
        {
            // DEAD CODE - Method exists but is never called
            return $"<div>{userContent}</div>"; // XSS vulnerability in dead code
        }

        private void UnreachableCodeAfterReturn(string input)
        {
            Console.WriteLine("This executes");
            return;
            
            // DEAD CODE - Unreachable code after return
            using (var connection = new SqlConnection(connectionString))
            {
                var vulnerableQuery = $"DELETE FROM Users WHERE id = {input}";
                var command = new SqlCommand(vulnerableQuery, connection);
                connection.Open();
                command.ExecuteNonQuery();
            }
        }

        private void ConditionalDeadCode()
        {
            const bool DEBUG_MODE = false;
            
            if (DEBUG_MODE) // This condition is always false
            {
                // DEAD CODE - This block never executes
                string adminPassword = "admin123"; // Hardcoded password in dead code
                ExecuteAdminCommand(adminPassword);
            }
        }

        private void ExecuteAdminCommand(string password)
        {
            // DEAD CODE - Only called from dead code path
            Console.WriteLine($"Admin command with password: {password}");
        }

        // ========== CATEGORY 2: FALSE_POSITIVE_SANITIZED ==========
        // Vulnerabilities that are properly sanitized
        
        public void FalsePositiveSanitizedXSS(string userInput)
        {
            // Input is properly HTML encoded before output
            string sanitizedInput = HttpUtility.HtmlEncode(userInput);
            Console.WriteLine($"Safe output: {sanitizedInput}");
        }

        public void FalsePositiveSanitizedSqlInjection(string userId)
        {
            // Using parameterized queries - proper sanitization
            using (var connection = new SqlConnection(connectionString))
            {
                var query = "SELECT * FROM Users WHERE id = @userId";
                var command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@userId", userId);
                connection.Open();
                command.ExecuteReader();
            }
        }

        public void FalsePositiveSanitizedPathTraversal(string fileName)
        {
            // Input validation and sanitization prevents path traversal
            string sanitizedFileName = Path.GetFileName(fileName); // Removes path components
            string safePath = Path.Combine(@"C:\SafeDirectory\", sanitizedFileName);
            
            if (File.Exists(safePath))
            {
                File.ReadAllText(safePath);
            }
        }

        // ========== CATEGORY 3: FALSE_POSITIVE_PROTECTED ==========
        // Vulnerabilities protected by compensating controls
        
        public void FalsePositiveProtectedFileAccess(string filePath)
        {
            // Strong access controls and validation prevent exploitation
            if (!IsAuthorizedUser())
            {
                throw new UnauthorizedAccessException("Access denied");
            }

            if (!IsValidFilePath(filePath))
            {
                throw new ArgumentException("Invalid file path");
            }

            // Additional protection: read-only access to safe directory
            string restrictedPath = Path.Combine(@"C:\ReadOnlyData\", Path.GetFileName(filePath));
            if (File.Exists(restrictedPath))
            {
                File.ReadAllText(restrictedPath);
            }
        }

        public void FalsePositiveProtectedSqlQuery(string searchTerm)
        {
            // Protected by multiple layers: authentication, authorization, and input validation
            if (!IsAuthenticated() || !HasReadPermission())
            {
                throw new UnauthorizedAccessException();
            }

            // Input length restriction and character validation
            if (searchTerm.Length > 50 || ContainsSqlKeywords(searchTerm))
            {
                throw new ArgumentException("Invalid search term");
            }

            // Even though not parameterized, strong controls make exploitation impractical
            using (var connection = new SqlConnection(connectionString))
            {
                var query = $"SELECT title FROM PublicArticles WHERE title LIKE '%{searchTerm}%'";
                var command = new SqlCommand(query, connection);
                connection.Open();
                command.ExecuteReader();
            }
        }

        // ========== CATEGORY 4: MUST_FIX ==========
        // High-risk, easily exploitable vulnerabilities
        
        public void MustFixSqlInjection(string userInput)
        {
            // CRITICAL: Direct SQL injection vulnerability
            using (var connection = new SqlConnection(connectionString))
            {
                var query = $"SELECT * FROM Users WHERE username = '{userInput}' AND password = '{GetUserPassword()}'";
                var command = new SqlCommand(query, connection);
                connection.Open();
                var result = command.ExecuteReader();
                
                if (result.HasRows)
                {
                    GrantAdminAccess(); // High impact if exploited
                }
            }
        }

        public void MustFixPathTraversal(string fileName)
        {
            // CRITICAL: Direct path traversal to sensitive files
            string filePath = $@"C:\WebRoot\uploads\{fileName}";
            string content = File.ReadAllText(filePath); // Can read any file on system
            Console.WriteLine(content);
        }

        public void MustFixCommandInjection(string userCommand)
        {
            // CRITICAL: Direct command injection
            var process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = $"/c {userCommand}"; // Direct command execution
            process.Start();
        }

        // ========== CATEGORY 5: GOOD_TO_FIX ==========
        // Lower risk vulnerabilities that should still be addressed
        
        public void GoodToFixWeakCrypto(string password)
        {
            // MEDIUM: Using weak MD5 hashing
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                string hashString = Convert.ToBase64String(hash);
                Console.WriteLine($"Weak hash: {hashString}");
            }
        }

        public void GoodToFixInformationDisclosure()
        {
            // MEDIUM: Detailed error information disclosure
            try
            {
                File.ReadAllText(@"C:\NonExistentFile.txt");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Detailed error: {ex.Message} - {ex.StackTrace}");
            }
        }

        public void GoodToFixWeakValidation(string email)
        {
            // MEDIUM: Weak input validation
            if (email.Contains("@"))
            {
                SendEmail(email); // Very basic validation, could be bypassed
            }
        }

        // ========== HELPER METHODS ==========
        
        private bool IsAuthorizedUser()
        {
            // Simulate strong authorization check
            return true; // Simplified for testing
        }

        private bool IsValidFilePath(string path)
        {
            // Simulate path validation
            return !path.Contains("..");
        }

        private bool IsAuthenticated()
        {
            return true; // Simplified for testing
        }

        private bool HasReadPermission()
        {
            return true; // Simplified for testing
        }

        private bool ContainsSqlKeywords(string input)
        {
            string[] sqlKeywords = { "DROP", "DELETE", "INSERT", "UPDATE", "EXEC" };
            return Array.Exists(sqlKeywords, keyword => 
                input.ToUpper().Contains(keyword));
        }

        private string GetUserPassword()
        {
            return "user_password"; // Simplified for testing
        }

        private void GrantAdminAccess()
        {
            Console.WriteLine("Admin access granted!");
        }

        private void SendEmail(string email)
        {
            Console.WriteLine($"Email sent to: {email}");
        }
    }

    // ========== ADDITIONAL DEAD CODE CLASSES ==========
    
    [Obsolete("This entire class is deprecated", true)]
    public class DeadCodeLegacyAuth
    {
        // DEAD CODE - Entire class is obsolete
        public bool ValidateUser(string username, string password)
        {
            // SQL injection in dead code
            var query = $"SELECT COUNT(*) FROM Users WHERE username='{username}' AND password='{password}'";
            return true;
        }
    }

    internal class UnusedUtilityClass
    {
        // DEAD CODE - This class is never instantiated or used
        public static void VulnerableFileHandler(string path)
        {
            // Path traversal in unused code
            File.Delete(path);
        }

        public static string UnsafeDeserialization(string jsonData)
        {
            // Deserialization vulnerability in dead code
            return jsonData; // Simplified for demo
        }
    }

#if DEBUG && FALSE
    // DEAD CODE - Conditional compilation that never compiles
    public class DeadConditionalCode
    {
        public void HardcodedCredentials()
        {
            string apiKey = "sk-1234567890abcdef"; // Hardcoded API key in dead code
            string dbPassword = "SuperSecret123!"; // Hardcoded DB password
        }
    }
#endif
}
