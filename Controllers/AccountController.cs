using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class AccountController : Controller
{
    private readonly AuthService _authService = new AuthService();

    public IActionResult Login(string username, string password)
    {
        if (_authService.Login(username, password))
            return Content("Login successful");
        else
            return Content("Invalid credentials");
    }

    // Real vulnerability: insecure deserialization
    public IActionResult Deserialize(string data)
    {
        var formatter = new BinaryFormatter();
        byte[] bytes = Convert.FromBase64String(data);
        using (var stream = new MemoryStream(bytes))
        {
            var obj = formatter.Deserialize(stream);
            return Content("Object deserialized");
        }
    }

    // Dead code: RCE via Process.Start
    private void ExecuteDangerousCommand()
    {
        System.Diagnostics.Process.Start("cmd.exe", "/C dir");
    }
}