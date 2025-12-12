using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using AuthWebApplication.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AuthWebApplication.Controllers;

[Authorize]
public class HomeController(AuthContext db, ILogger<HomeController> logger) : Controller
{
    private readonly ILogger<HomeController> _logger = logger;
    private readonly AuthContext _db = db;

    public async Task<IActionResult> Index()
    {
        var uname = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        var user = await _db.Users.FirstOrDefaultAsync(x => x.Username == uname);
        return View(user);
    }

    [HttpPost]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDTO changePasswordDTO)
    {
        if(string.IsNullOrEmpty(changePasswordDTO.OldPassword) || string.IsNullOrEmpty(changePasswordDTO.NewPassword))
        {
            _logger.LogWarning("Change password failed: invalid");
            return BadRequest(new { message = "Không thể đổi mật khẩu" });            
        }
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Change password failed: invalid model");
            return BadRequest(new { message = "Không thể đổi mật khẩu" });
        }
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
