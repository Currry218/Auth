using System.ComponentModel.DataAnnotations;

namespace AuthWebApplication.Models;

public class LoginDTO
{
    required public string Loginname { get; set; }
    public required string Password { get; set; }
}