using eTickets.Data.Services.Static;
using eTickets.Data.ViewModels;
using eTickets.Data;
using eTickets.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.WebUtilities;
using System.Text.Encodings.Web;
using System.Text;
using System;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.Net;
using Microsoft.AspNetCore.Server.HttpSys;

namespace eTickets.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LoginVM> _logger;
        private readonly IEmailSender _emailSender;
        private readonly AppDbContext _context;

        public AccountController(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager, ILogger<LoginVM> logger,
            IEmailSender emailSender, AppDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _context = context;
        }

        public async Task<IActionResult> Users()
        {
            var users = await _context.Users.ToListAsync();
            return View(users);
        }


        public IActionResult Login() => View(new LoginVM());

        [HttpPost]
        public async Task<IActionResult> Login(LoginVM loginVM)
        {
            if (!ModelState.IsValid) return View(loginVM);

            var user = await _userManager.FindByEmailAsync(loginVM.EmailAddress);
            if (user != null)
            {
                var passwordCheck = await _userManager.CheckPasswordAsync(user, loginVM.Password);
                if (passwordCheck)
                {
                    var result = await _signInManager.PasswordSignInAsync(user, loginVM.Password, false, false);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Index", "Movies");
                    }
                }
                TempData["Error"] = "Wrong credentials. Please, try again!";
                return View(loginVM);
            }

            TempData["Error"] = "Wrong credentials. Please, try again!";
            return View(loginVM);
        }


        public IActionResult Register() => View(new RegisterVM());

        [HttpPost]
        public async Task<IActionResult> Register(RegisterVM registerVM)
        {
            //if (!ModelState.IsValid) return View(registerVM);
            var user = await _userManager.FindByEmailAsync(registerVM.EmailAddress);
            if (user != null)
            {
                TempData["Error"] = "This email address is already in use";
                return View(registerVM);
            }
            var newUser = new ApplicationUser()
            {
                FullName = registerVM.FullName,
                Email = registerVM.EmailAddress,
                UserName = registerVM.FullName
            };
            var newUserResponse = await _userManager.CreateAsync(newUser, registerVM.Password);
            if (newUserResponse.Succeeded)
            {
                await _userManager.AddToRoleAsync(newUser, UserRoles.User);
                _logger.LogInformation("Vừa tạo mới tài khoản thành công.");
                var userConfirm = await _userManager.FindByEmailAsync(registerVM.EmailAddress);
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(userConfirm);
                //code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callBackURL = Url.Action("ConfirmEmail", "Account", new { userId = userConfirm.Id, confirmCode = code }, protocol: Request.Scheme);
                //var callBackURL = "https://localhost:44369/Account/Login";
                await _emailSender.SendEmailAsync(registerVM.EmailAddress, "Confirm your account", $"Confirm your email: <a href='{HtmlEncoder.Default.Encode(callBackURL)}'>Bấm vào đây</a>.");
            }
            return View("ConfirmEmail");
            //return View("RegisterCompleted");
        }


        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string confirmCode)
        {
            if (userId == null || confirmCode == null)
            {
                return View("Error");
            }
            var user = await _userManager.FindByIdAsync(userId);
            //var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(confirmCode));
            var result = await _userManager.ConfirmEmailAsync(user, confirmCode);
            return View(result.Succeeded ? "Login" : "AccessDenied");
        }


        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Movies");
        }

        public IActionResult AccessDenied(string ReturnUrl)
        {
            return View();
        }


        public IActionResult ForgotPassword()
        {
            return View();
        }


        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordVM model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (ModelState.IsValid)
            {
                if (user == null)
                {
                    TempData["Error"] = "Wrong email. Please, try again!";
                    return View(model);
                }
            }

            string code = await _userManager.GeneratePasswordResetTokenAsync(user);
            //code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callBackURL = Url.Action("ResetPassword", "Account", new { code = code }, protocol: Request.Scheme);
            await _emailSender.SendEmailAsync(model.Email, "Confirm your account", $"Confirm your email: <a href='{HtmlEncoder.Default.Encode(callBackURL)}'>Bấm vào đây</a>.");
            return View("ConfirmEmail");
        }

        public IActionResult ResetPassword(string code)
        {
            if (code == null) { View("AccessDenied"); }
            return View();
        }


        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordVM model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return View();
            }
            //byte[] buffer = Convert.FromBase64String(model.code);
            //string decoded = Encoding.UTF8.GetString(buffer);
            var result = await _userManager.ResetPasswordAsync(user, model.code, model.newPassword);
            if (result.Succeeded)
            {
                return View("ResetPasswordConfirm");
            }

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLogin(string provider, string returnUrl = null)
        {
            // Kiểm tra yêu cầu dịch vụ provider tồn tại
            var listprovider = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            var provider_process = listprovider.Find((m) => m.Name == provider);
            if (provider_process == null)
            {
                return NotFound("Dịch vụ không chính xác: " + provider);
            }
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        public async Task<ActionResult> ExternalLoginCallback(string ReturnUrl)
        {

            var info = await _signInManager.GetExternalLoginInfoAsync();

            if (info == null)
            {
                //ErrorMessage = "Lỗi thông tin từ dịch vụ đăng nhập.";
                return RedirectToAction("Login");
            }

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);

            if (result.Succeeded)
            {
                // User đăng nhập thành công vào hệ thống theo thông tin info
                return RedirectToAction("Index", "Movies");
            }


            string externalMail = null;

            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
            {
                externalMail = info.Principal.FindFirstValue(ClaimTypes.Email);
            }
            var userWithexternalMail = (externalMail != null) ? (await _userManager.FindByEmailAsync(externalMail)) : null;

            if (userWithexternalMail == null) { return View("ExternalLogin", new ExternalLoginConfirmVM { Email = externalMail }); }

            var resultAdd = await _userManager.AddLoginAsync(userWithexternalMail, info);


            if (resultAdd.Succeeded)
            {
                // Thực hiện login    
                await _signInManager.SignInAsync(userWithexternalMail, isPersistent: false);
                return RedirectToAction("Index", "Movies");
            }
            else
            {
                return View("ExternalLogin");
            }



        }

        public async Task<IActionResult> Confirmation(string Email)
        {
            var newUser = new ApplicationUser()
            {
                UserName = Email,
                Email = Email,
            };
            var result = await _userManager.CreateAsync(newUser);
            var userConfirm = await _userManager.FindByEmailAsync(Email);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(userConfirm);
            //code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callBackURL = Url.Action("ConfirmEmail", "Account", new { userId = userConfirm.Id, confirmCode = code }, protocol: Request.Scheme);
            //var callBackURL = "https://localhost:44369/Account/Login";
            await _emailSender.SendEmailAsync(Email, "Confirm your account", $"Confirm your email: <a href='{HtmlEncoder.Default.Encode(callBackURL)}'>Bấm vào đây</a>.");
          
            if(result.Succeeded)
            {
                return View("Login");
            }
            return View();
        }
    }
}