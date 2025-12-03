using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using dotenv.net;

using CloudinaryDotNet;
using CloudinaryDotNet.Actions;

using MailKit.Net.Smtp;
using MailKit;
using MimeKit;

using AuthWebApplication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
// using AuthWebApplication.Data;
// [Route("api/auth")]
// [ApiController]
public class AuthController : Controller
{
    private readonly AuthContext _db;
    private readonly ILogger<AuthController> _logger;
    private Cloudinary _cloudinary;

    public AuthController(AuthContext db, ILogger<AuthController> logger)
    {
        _db = db;
        _logger = logger;

        DotEnv.Load(options: new DotEnvOptions(probeForEnv: true));
        _cloudinary = new Cloudinary(Environment.GetEnvironmentVariable("CLOUDINARY_URL"));
        _cloudinary.Api.Secure = true;
    }

    [HttpGet]
    public IActionResult Login()
    {
        var u = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        if(u != null) return RedirectToAction("Index","Home");
        return View();
    } 

    [HttpGet]
    public IActionResult Index() => RedirectToAction("Login");

    [HttpGet]
    public IActionResult Register() {
        var u = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        if(u != null) return RedirectToAction("Index","Home");
        return View();
    } 

    [HttpGet]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
    // return Unauthorized(new { message = "Invalid username or password" });
    // return NotFound(new { message = "User not found" });

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginDTO dto)
    {
        var user = _db.Users.FirstOrDefault(u => u.Username == dto.Loginname || u.Email == dto.Loginname);
        if (user == null) return Unauthorized(new { message = "Invalid username or password" });

        if (!BCrypt.Net.BCrypt.Verify(dto.Password, user.Password))
            return Unauthorized(new { message = "Invalid username or password" });

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
        };

        var identity = new ClaimsIdentity(claims, "Login");
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(principal);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal
            // authProperties
            );
        return Ok(new { message = "Login success" });
        // return RedirectToAction("Index","Home");
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> Register(string fullname, string email, string address, string sdt, string uname, string password, IFormFile avt)
    {
        var avtUrl = "https://dummyimage.com/150x150/ced4da/ffffff.png&text=Avatar";
        if (avt != null)
        {
            var uploadParams = new ImageUploadParams()
            {
                File = new FileDescription(avt.FileName, avt.OpenReadStream()),
                Transformation = new Transformation().Width(150).Crop("limit")
            };

            var uploadResult = await _cloudinary.UploadAsync(uploadParams);
            // Console.WriteLine(uploadResult);
            // Console.WriteLine(uploadResult.Url);
            avtUrl = uploadResult.Url.ToString();
            if (uploadResult.Error != null)
            {
                return StatusCode(500, uploadResult.Error.Message);
            }

        }
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);
        var user = new User()
        {
            FullName = fullname ?? "No full name",
            Username = uname,
            Email = email,
            Address = address ?? "No address",
            Role = "Role",
            Avatar = avtUrl,
            Password = passwordHash,

        };
        // Added successfully
        _db.Add(user);
        _db.SaveChanges();

        return RedirectToAction("Login");
    }

}