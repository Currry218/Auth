using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthWebApplication.Models;
using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using dotenv.net;

public class AuthController : Controller
{
    private readonly AuthContext _db;
    private readonly ILogger<AuthController> _logger;
    private readonly PasswordHasher<User> _hasher = new();
    private Cloudinary cloudinary;

    public AuthController(AuthContext db, ILogger<AuthController> logger)
    {
        _db = db;
        _logger = logger;

        DotEnv.Load(options: new DotEnvOptions(probeForEnv: true));
        cloudinary = new Cloudinary(Environment.GetEnvironmentVariable("CLOUDINARY_URL"));
        cloudinary.Api.Secure = true;
    }

    [HttpGet]
    public IActionResult Login() => View();

    [HttpGet]
    public IActionResult Index() => RedirectToAction("Login");

    [HttpGet]
    public IActionResult Register() => View();

    [HttpPost]
    public async Task<IActionResult> Login(string loginname, string password)
    {
        if (string.IsNullOrWhiteSpace(loginname) || string.IsNullOrWhiteSpace(password))
        {
            ModelState.AddModelError("", "Username and password are required.");
            return RedirectToAction("Error", "Home");
            // return NotFound();
        }
        var user = _db.Users.FirstOrDefault(u => (u.Username == loginname) || (u.Email == loginname));
        if (user != null)
        {
            // System.Console.WriteLine("UNAME " + loginname + " PSW " + password + " HAsh ");
            var result = BCrypt.Net.BCrypt.Verify(password, user.Password);
            // System.Console.WriteLine(result);
            return Ok(user);

        } else
        {
            ModelState.AddModelError("", "Can't find user");
            return RedirectToAction("Error", "Home");
        }
    }
    
    [HttpPost]
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

            var uploadResult = await cloudinary.UploadAsync(uploadParams);
            System.Console.WriteLine(uploadResult);
            System.Console.WriteLine(uploadResult.Url);
            avtUrl = uploadResult.Url.ToString();
            if (uploadResult.Error != null)
            {
                return StatusCode(500, uploadResult.Error.Message);
            }

        }
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        var user = new User()
        {
            FullName = fullname,
            Username = uname,
            Email = email,
            Address = address,
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