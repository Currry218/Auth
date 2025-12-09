using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using AuthWebApplication.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AuthWebApplication.Controllers;

// TODO: try to get user in whole class then use 
public class HomeController(AuthContext db, ILogger<HomeController> logger) : Controller
{
    private readonly ILogger<HomeController> _logger = logger;
    private readonly AuthContext _db = db;

    [Authorize]
    public async Task<IActionResult> Index()
    {
        var uname = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        var user = await _db.Users.FirstOrDefaultAsync(x => x.Username == uname);
        return View(user);
    }

    [HttpPost]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDTO changePasswordDTO)
    {
        var uname = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        
        var user = await _db.Users.FirstOrDefaultAsync(x => x.Username == uname);
        if(user == null)
        {
            _logger.LogInformation("Cant find user");
            return NotFound(new {message = "Không tìm thấy người dùng"});
        }

        if(!BCrypt.Net.BCrypt.Verify(user.Username + changePasswordDTO.OldPassword, user.Password))
        {

            _logger.LogInformation("Wrong password");
            return BadRequest(new {message = "Sai mật khẩu cũ"});
            
        }
        user.Password = BCrypt.Net.BCrypt.HashPassword(changePasswordDTO.NewPassword);
        _db.SaveChanges();

        return Ok(new {messsage = "Đổi mật khẩu thành công"});
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

}
