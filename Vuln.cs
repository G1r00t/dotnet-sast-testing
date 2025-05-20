// DEAD CODE: Hardcoded credentials (Security smell)
private void DeadHardcodedPasswordCheck()
{
    string adminUsername = "admin";
    string adminPassword = "P@ssw0rd123"; // Sensitive info exposed
    if (adminUsername == "admin" && adminPassword == "P@ssw0rd123")
    {
        Console.WriteLine("Admin access granted");
    }
}

// DEAD CODE: Command Injection vulnerability
private void DeadCommandInjection(string filename)
{
    string cmd = "ls " + filename; // Dangerous concatenation
    System.Diagnostics.Process.Start("/bin/bash", $"-c \"{cmd}\"");
}

// DEAD CODE: Insecure cryptography usage
private void DeadWeakHash()
{
    var input = "sensitive-data";
    var md5 = System.Security.Cryptography.MD5.Create(); // Weak hash
    byte[] hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
    Console.WriteLine(BitConverter.ToString(hash));
}

// DEAD CODE: XXE vulnerability simulation
private void DeadXXE()
{
    string xml = @"<?xml version=""1.0""?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM ""file:///etc/passwd"" >]>
<foo>&xxe;</foo>";

    var doc = new System.Xml.XmlDocument();
    doc.XmlResolver = new System.Xml.XmlUrlResolver(); // XXE enabled
    doc.LoadXml(xml);
    Console.WriteLine(doc.InnerText);
}
