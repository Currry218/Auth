using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using dotenv.net;

// using User.Data;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// builder.Services.AddDbContext<AuthContext>();
// builder.Services.AddDbContext<AuthContext>(options => options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddDbContext<AuthContext>(options => options.UseNpgsql(Environment.GetEnvironmentVariable("DB_CONNECTION_STRING")));


// add cookie authentication
builder.Services.AddDistributedMemoryCache(); // required for session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // session timeout
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Auth/Login";
        options.LogoutPath = "/Auth/Logout";
        options.AccessDeniedPath = "/Forbidden";
        // options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        // options.SlidingExpiration = true;
    });


builder.Services.AddControllersWithViews();

var app = builder.Build();
// var cookiePolicyOptions = new CookiePolicyOptions
// {
//     MinimumSameSitePolicy = SameSiteMode.Strict,
// };

// app.UseCookiePolicy(cookiePolicyOptions);
// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
// app.MapRazorPages();
// app.MapDefaultControllerRoute();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Auth}/{action=Login}/{id?}")
    .WithStaticAssets();

app.Run();