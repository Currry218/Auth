
using Microsoft.EntityFrameworkCore;
using AuthWebApplication.Models;

public class AuthContext: DbContext
{
    public DbSet<User> Users {get; set;}
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlServer("Server=localhost;Database=AuthDB;Trusted_Connection=True;TrustServerCertificate=True");
    }
}
