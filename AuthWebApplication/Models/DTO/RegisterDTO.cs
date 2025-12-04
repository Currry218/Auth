using System.ComponentModel.DataAnnotations;

namespace AuthWebApplication.Models;

public class RegisterDTO
{
    required public string Username { get; set; }
    required public string Email { get; set; }
    required public string Password { get; set; }
    public string? FullName { get; set; }
    public string? Address { get; set; }
    public string? PhoneNumber { get; set; }
    public string? Role { get; set; }
    public IFormFile? Avatar { get; set; }
}