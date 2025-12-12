using System.ComponentModel.DataAnnotations;

namespace AuthWebApplication.Models;

public class LoginDTO
{
    required public string Loginname { get; set; }
    required public string Password { get; set; }
}