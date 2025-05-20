using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

// Add controllers
builder.Services.AddControllers();

var app = builder.Build();

// Map controllers
app.MapControllers();

// Add a default route to call the vulnerable endpoint for demonstration
app.MapGet("/vuln-demo", (Microsoft.AspNetCore.Mvc.ControllerBase controller, Microsoft.AspNetCore.Http.HttpRequest request) =>
{
    // Simulate a vulnerable call to the UserController's GetUser method
    // This is for demonstration/testing tools like Semgrep
    var username = request.Query["username"].ToString();
    var userController = new VulnerableWebApp.Controllers.UserController();
    return userController.VulnerableFunction(username);
});

app.Run();

// See https://aka.ms/new-console-template for more information