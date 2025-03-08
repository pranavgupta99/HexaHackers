using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using HexaHackers.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace HexaHackers.Controllers;

public class HomeController : Controller
{
    private UserContext _userContext;

    public HomeController(UserContext userContext)
    {
        _userContext = userContext;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    [Route("Register")]
    public IActionResult Registration()
    {
        if (User.Identity != null && User.Identity.IsAuthenticated)
        {
            return RedirectToAction("SecurePage");
        }
        return View();
    }

    [Route("Register")]
    [HttpPost]
    public IActionResult Registration(RegistrationViewModel model)
    {
        if (ModelState.IsValid)
        {
            var isDuplicate = _userContext.Users.Any(u => u.Username == model.Username || u.Email == model.Email);
            if (isDuplicate)
            {
                if (_userContext.Users.Any(u => u.Username == model.Username))
                {
                    ModelState.AddModelError("Username", "This username is already taken.");
                }

                if (_userContext.Users.Any(u => u.Email == model.Email))
                {
                    ModelState.AddModelError("Email", "This email is already registered.");
                }

                return View(model); // Return the form with errors
            }
            User user = new User();
            user.Username = model.Username;
            user.Email = model.Email;
            user.PasswordHash = model.PasswordHash;
            _userContext.Users.Add(user);
            _userContext.SaveChanges();

            ModelState.Clear();
            ViewBag.Message = $"{user.Username} registered successfully. Please login";

            return View();
        }
        return View(model);
    }

    [Route("LogIn")]
    public IActionResult Login()
    {
        if (User.Identity != null && User.Identity.IsAuthenticated)
        {
            return RedirectToAction("SecurePage");
        }
        return View();
    }

    [Route("LogIn")]
    [HttpPost]
    public IActionResult Login(LoginViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = _userContext.Users.Where(x => x.Username == model.Username && x.PasswordHash == model.PasswordHash).FirstOrDefault();
            if (user != null)
            {
                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Username),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Role, "User")
                    };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                return RedirectToAction("SecurePage");
            }
            else
            {
                ModelState.AddModelError("", "Username or Password is not correct");
            }
            return View();
        }
        return View(model);
    }

    [Route("LogOut")]
    public IActionResult LogOut()
    {
        HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index");
    }
}
