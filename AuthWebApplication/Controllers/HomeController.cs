using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using AuthWebApplication.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using NuGet.Protocol;
using System.Security.Claims;

namespace AuthWebApplication.Controllers;

public class HomeController(AuthContext db, ILogger<HomeController> logger) : Controller
{
    private readonly ILogger<HomeController> _logger = logger;
    private readonly AuthContext _db = db;

    [Authorize]
    public async Task<IActionResult> Index()
    {
        var uname = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        Console.WriteLine(uname);
        var user = await _db.Users.FirstOrDefaultAsync(x => x.Username == uname);
        return View(user);
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

}
