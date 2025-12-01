using System.ComponentModel.DataAnnotations;

namespace AuthWebApplication.Models;

public class User
{
    public int Id { get; set; }
    required public string Username { get; set; }
    required public string Email { get; set; }
    public required string Password { get; set; }
    public string? FullName { get; set; }
    public string? Address { get; set; }
    public string? PhoneNumber { get; set; }
    public string? Role { get; set; }
    public string? Avatar { get; set; }
}