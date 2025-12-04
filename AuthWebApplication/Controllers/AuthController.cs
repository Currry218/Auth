using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using dotenv.net;

using CloudinaryDotNet;
using CloudinaryDotNet.Actions;

using MailKit.Net.Smtp;
using MimeKit;

using AuthWebApplication.Models;
using Microsoft.AspNetCore.Authentication.Cookies;

public class AuthController : Controller
{
    private readonly AuthContext _db;
    private readonly ILogger<AuthController> _logger;
    private readonly Cloudinary _cloudinary;

    public AuthController(AuthContext db, ILogger<AuthController> logger)
    {
        _db = db;
        _logger = logger;

        DotEnv.Load(options: new DotEnvOptions(probeForEnv: true));

        var cloudUrl = Environment.GetEnvironmentVariable("CLOUDINARY_URL");
        _cloudinary = new Cloudinary(cloudUrl);
        _cloudinary.Api.Secure = true;
    }

    [HttpGet]
    public IActionResult Login()
    {
        var username = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        if (username != null)
        {
            _logger.LogInformation("User {User} already logged in", username);
            return RedirectToAction("Index", "Home");
        }

        return View();
    }

    [HttpGet]
    public IActionResult Index() => RedirectToAction("Login");

    [HttpGet]
    public IActionResult ResetPassword() {
        ViewBag.User = TempData["username"];
        return View();
    } 

    [HttpGet]
    public IActionResult Register()
    {
        var u = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        if (u != null) return RedirectToAction("Index", "Home");

        return View();
    }

    [HttpGet]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        _logger.LogInformation("User logged out successfully");
        return RedirectToAction("Login");
    }

    [HttpPost]
    public async Task<IActionResult> Login([FromBody] LoginDTO dto)
    {
        _logger.LogInformation("Login attempt for account {Acc}", dto.Loginname);

        var user = _db.Users.FirstOrDefault(u =>
            u.Username == dto.Loginname || u.Email == dto.Loginname);

        if (user == null)
        {
            _logger.LogWarning("Login failed: account not found");
            return Unauthorized(new { message = "Invalid username or password" });
        }

        if (!BCrypt.Net.BCrypt.Verify(dto.Password, user.Password))
        {
            _logger.LogWarning("Login failed: wrong password for {Acc}", dto.Loginname);
            return Unauthorized(new { message = "Invalid username or password" });
        }

        var claims = new List<Claim> {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(principal);

        _logger.LogInformation("User {User} logged in successfully", user.Username);

        return Ok(new { message = "Login success" });
    }


    [HttpPost]
    public async Task<IActionResult> Register([FromForm] RegisterDTO dto)
    {
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Register failed: invalid model");
            return BadRequest("Invalid register data");
        }

        _logger.LogInformation("Register request for email {Email}", dto.Email);

        string avatarUrl = "https://dummyimage.com/150x150/ced4da/ffffff.png&text=Avatar";

        // Upload avatar if exists
        if (dto.Avatar != null)
        {
            _logger.LogInformation("Uploading avatar {Name}", dto.Avatar.FileName);

            var uploadParams = new ImageUploadParams
            {
                File = new FileDescription(dto.Avatar.FileName, dto.Avatar.OpenReadStream()),
                // Transformation = new Transformation().Width(150).Height(150).Crop("fill")
            };

            var uploadResult = await _cloudinary.UploadAsync(uploadParams);

            if (uploadResult.Error != null)
            {
                _logger.LogError("Avatar upload failed: {Err}", uploadResult.Error.Message);
                return StatusCode(500, uploadResult.Error.Message);
            }

            avatarUrl = uploadResult.Url.ToString();
            _logger.LogInformation("Avatar uploaded successfully: {Url}", avatarUrl);
        }

        var hashed = BCrypt.Net.BCrypt.HashPassword(dto.Password);

        var user = new User
        {
            FullName = dto.FullName,
            Username = dto.Username,
            Password = hashed,
            Email = dto.Email,
            Role = dto.Role ?? "User",
            Address = dto.Address,
            PhoneNumber = dto.PhoneNumber,
            Avatar = avatarUrl,
        };

        _db.Users.Add(user);
        _db.SaveChanges();

        _logger.LogInformation("New user registered: {Email}", dto.Email);

        return Ok(new { message = "Register success" });
    }

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