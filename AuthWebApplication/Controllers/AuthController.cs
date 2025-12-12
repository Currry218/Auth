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
    public IActionResult Index() => RedirectToAction("Login");

    [HttpGet]
    public IActionResult Login()
    {
        var username = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        if (username != null)
        {
            _logger.LogInformation("User {User} already logged in", username);
            return RedirectToAction("Index", "Home");
        }
        ViewBag.Message = TempData["message"];
        return View("Login/Index");
    }

    [HttpGet]
    public IActionResult ResetPassword()
    {
        if (TempData["username"] == null)
        {
            return RedirectToAction("Login/Index"); // or return Unauthorized()
        }


        TempData.Keep("username");

        ViewBag.User = TempData["username"];
        return View();
    }


    [HttpGet]
    public IActionResult Register()
    {
        var username = HttpContext.User.FindFirstValue(ClaimTypes.Name);
        if (username != null)
        {
            _logger.LogInformation("User {User} already logged in", username);
            return RedirectToAction("Index", "Home");
        }

        return View("Register/Index");
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
        if (string.IsNullOrEmpty(dto.Loginname) || string.IsNullOrEmpty(dto.Password))
        {
            _logger.LogWarning("Login failed: invalid");
            return BadRequest(new { message = "Thông tin đăng nhập không hợp lệ" });
        }
        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Login failed: invalid model");
            return BadRequest(new { message = "Thông tin đăng nhập không hợp lệ" });
        }
        _logger.LogInformation("Login attempt for account {Acc}", dto.Loginname);

        var user = _db.Users.FirstOrDefault(u =>
            u.Username == dto.Loginname || u.Email == dto.Loginname);

        if (user == null)
        {
            _logger.LogWarning("Login failed: account not found");
            return Unauthorized(new { message = "Tên đăng nhập hoặc mật khẩu không hợp lệ" });
        }

        if (!BCrypt.Net.BCrypt.Verify(user.Username + dto.Password, user.Password))
        {
            _logger.LogWarning("Login failed: wrong password for {Acc}", dto.Loginname);
            return Unauthorized(new { message = "Tên đăng nhập hoặc mật khẩu không hợp lệ" });
        }

        var claims = new List<Claim> {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(principal);

        _logger.LogInformation("User {User} logged in successfully", user.Username);

        return Ok(new { message = "Đăng nhập thành công" });
        // return RedirectToAction("Index","Home");
    }


    [HttpPost]
    public async Task<IActionResult> Register([FromForm] RegisterDTO dto)
    {
        if (string.IsNullOrEmpty(dto.Email) || string.IsNullOrEmpty(dto.Username) || string.IsNullOrEmpty(dto.Password))
        {
            _logger.LogWarning("Register failed: invalid");
            return BadRequest(new { message = "Thông tin đăng ký không hợp lệ" });
        }


        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Register failed: invalid model");
            return BadRequest(new { message = "Thông tin đăng ký không hợp lệ" });
        }

        _logger.LogInformation("Register request for email {Email}", dto.Email);

        var _user = _db.Users.FirstOrDefault(u =>
                    u.Username == dto.Username || u.Email == dto.Email);

        if (_user != null)
        {
            _logger.LogWarning("Register failed: Same username or email");
            return BadRequest(new { message = "Đã tồn tại tài khoản có cùng tên đăng nhập/email" });
        }

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
                return StatusCode(500, "Không thể lưu avatar");
            }

            avatarUrl = uploadResult.Url.ToString();
            _logger.LogInformation("Avatar uploaded successfully: {Url}", avatarUrl);
        }
        var hashed = BCrypt.Net.BCrypt.HashPassword(dto.Username + dto.Password);
        var user = new User
        {
            FullName = dto.FullName,
            Username = dto.Username,
            Password = hashed,
            Email = dto.Email,
            Role = dto.Role ?? "Phòng ban 1",
            Address = dto.Address,
            PhoneNumber = dto.PhoneNumber,
            Avatar = avatarUrl,
        };

        _db.Users.Add(user);
        _db.SaveChanges();

        _logger.LogInformation("New user registered: {Email}", dto.Email);

        TempData["message"] = "Đăng ký thành công!";
        return Ok(new { message = "Đăng ký thành công" });
    }

    [HttpPost]
    public IActionResult ForgotPassword([FromForm] string account)
    {
        _logger.LogInformation("Password reset requested for {Acc}", account);

        var user = _db.Users.FirstOrDefault(u =>
            u.Username == account || u.Email == account);

        if (user == null)
        {
            _logger.LogWarning("Password reset failed: user not found");
            return NotFound(new { message = "Không tìm thấy người dùng" });
        }

        string plainOtp = new Random().Next(100000, 999999).ToString();

        string hashOtp = BCrypt.Net.BCrypt.HashPassword(plainOtp);
        user.ResetToken = hashOtp;
        user.Expire = DateTime.UtcNow.AddMinutes(15);
        _db.SaveChanges();

        _logger.LogInformation("OTP generated for {User}", user.Email);

        // Email sending
        var gmail = Environment.GetEnvironmentVariable("GMAIL");
        var psw = Environment.GetEnvironmentVariable("GMAIL_PSW");

        var msg = new MimeMessage();
        msg.From.Add(new MailboxAddress("Auth System", gmail));
        msg.To.Add(MailboxAddress.Parse(user.Email));
        msg.Subject = "Password Reset";
        msg.Body = new TextPart("html")
        {
            Text = $"<p>Hi,</p><p>We received a request to reset your password.</p><p>Your OTP code is:</p><h2 style='letter-spacing: 4px;'>{plainOtp}</h2><p>This code will expire in 5 minutes.</p><p>If you didn't request a password reset, please ignore this email.</p><br><p>Thanks,<br>Your App Team</p>"
        };

        using var smtp = new SmtpClient();
        smtp.Connect("smtp.gmail.com", 465, true);
        smtp.Authenticate(gmail, psw);
        smtp.Send(msg);
        smtp.Disconnect(true);

        _logger.LogInformation("OTP email sent to {Email}", user.Email);

        return Ok(new { message = "Đã gửi OTP về mail của bạn" });
    }

    [HttpPost]
    public IActionResult VerifyOTP([FromForm] string account, [FromForm] string OTP)
    {
        _logger.LogInformation("Verify OTP for {Acc}", account);

        var user = _db.Users.FirstOrDefault(u =>
            u.Username == account || u.Email == account);

        if (user == null) return NotFound(new { message = "Không tìm thấy người dùng"});

        if (user.Expire < DateTime.UtcNow)
        {
            _logger.LogWarning("OTP expired for {Acc}", account);
            return BadRequest(new { message = "OTP đã hết hạn" });
        }

        if (!BCrypt.Net.BCrypt.Verify(OTP, user.ResetToken))
        {
            _logger.LogWarning("OTP invalid for {Acc}", account);
            return BadRequest(new { message = "OTP không hợp lệ" });
        }

        user.ResetToken = null;
        user.Expire = null;
        _db.SaveChanges();

        _logger.LogInformation("OTP verified for {Acc}", account);

        TempData["username"] = user.Username;
        return RedirectToAction("ResetPassword");
    }

    [HttpPost]
    public IActionResult ResetPassword([FromForm] string username, [FromForm] string newPassword)
    {
        _logger.LogInformation("ResetPassword called for {User}", username);

        var user = _db.Users.FirstOrDefault(u => u.Username == username);
        if(string.IsNullOrEmpty(newPassword))
        {
            _logger.LogWarning("Reset password failed: invalid");
            return BadRequest(new { message = "Không thể đổi mật khẩu" });            
        }
        if (user == null)
        {
            _logger.LogWarning("Reset password failed: user not found");
            return NotFound(new { message = "Không tìm thấy người dùng" });
        }
        user.Password = BCrypt.Net.BCrypt.HashPassword(user.Username + newPassword);
        _db.SaveChanges();

        _logger.LogInformation("Password reset successfully for {User}", username);

        return Ok(new { message = "Đổi mật khẩu thành công" });
    }
}

