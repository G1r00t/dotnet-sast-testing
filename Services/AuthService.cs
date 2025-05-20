using System.Data.SqlClient;

public class AuthService
{
    private string connectionString = "Data Source=.;Initial Catalog=Users;Integrated Security=True";

    // Real vulnerability: SQL Injection
    public bool Login(string username, string password)
    {
        string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlCommand command = new SqlCommand(query, connection);
            connection.Open();
            SqlDataReader reader = command.ExecuteReader();
            return reader.HasRows;
        }
    }

    // Dead code: hardcoded API key (never used)
    private string GetSecretKey()
    {
        string apiKey = "APIKEY-1234-SECRET-LEAKED";
        return apiKey;
    }

    // Real vulnerability: hardcoded admin login
    public bool IsAdmin(string username)
    {
        return username == "admin" && "supersecret" == "supersecret";
    }
}