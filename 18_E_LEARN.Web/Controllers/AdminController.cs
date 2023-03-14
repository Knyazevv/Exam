using _18_E_LEARN.BusinessLogic.Services;
using _18_E_LEARN.DataAccess.Data.Models.Categories;
using _18_E_LEARN.DataAccess.Data.Models.User;
using _18_E_LEARN.DataAccess.Data.ViewModels.Course;
using _18_E_LEARN.DataAccess.Data.ViewModels.User;
using _18_E_LEARN.DataAccess.Validation.Course;
using _18_E_LEARN.DataAccess.Validation.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Security.Claims;

namespace _18_E_LEARN.Web.Controllers
{
    [Authorize]
    public class AdminController : Controller
    {
        private readonly UserService _userService;

        public AdminController(UserService userService)
        {
            _userService = userService;
        }

        public IActionResult Index()
        {
            return View();
        }
        #region Users
        public async Task<IActionResult> Users()
        {
            var result = await _userService.GetAllUsers();
            if (result.Success)
            {
                return View(result.Payload);
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UserSettings(UpdateProfileVM model)
        {
            var validator = new UpdateProfileValidation();
            var validationresult = await validator.ValidateAsync(model);
            if (validationresult.IsValid)
            {
                var result = await _userService.UpdateProfileAsync(model);
                if (result.Success)
                {
                    return RedirectToAction("SignIn", "Admin");
                }
                ViewBag.AuthError = result.Message;
                return View(model);

            }
            return View(model);
        }

        public async Task<IActionResult> UserSettings()
        {
            var userId = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _userService.GetUserForSettingsAsync(userId);
            if (result.Success)
            {
                return View(result.Payload);
            }
            return View();
        }

        public async Task<IActionResult> Profile()
        {
            var userId = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var result = await _userService.GetUserProfileAsync(userId);
            if (result.Success)
            {
                return View(result.Payload);
            }
            return View();
        }

        [AllowAnonymous]
        public IActionResult SignIn()
        {
            var user = HttpContext.User.Identity.IsAuthenticated;
            if (user)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> SignIn(LoginUserVM model)
        {
            var valdator = new LoginUserValidation();
            var validationresult = await valdator.ValidateAsync(model);
            if (validationresult.IsValid)
            {
                var result = await _userService.LoginUserAsync(model);
                if (result.Success)
                {
                    return RedirectToAction("Index", "Admin");
                }
                ViewBag.AuthError = result.Message;
                return View(model);
            }
            return View(model);
        }

        [AllowAnonymous]
        public IActionResult SignUp()
        {
            var user = HttpContext.User.Identity.IsAuthenticated;
            if (user)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> SignUp(RegisterUserVM model)
        {
            var validator = new RegisterUserValidation();
            var validationresult = await validator.ValidateAsync(model);
            if (validationresult.IsValid)
            {
                var result = await _userService.RegisterUserAsync(model);
                if (result.Success)
                {
                    return RedirectToAction("SignIn", "Admin");
                }

                ViewBag.AuthError = result.Message;
                return View(model);
            }
            ViewBag.AuthError = validationresult.Errors.First();
            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            var result = await _userService.LogoutUserAsync();
            if (result.Success)
            {
                return RedirectToAction("Index", "Home");
            }
            return RedirectToAction("Index", "Admin");
        }

        public async Task<IActionResult> EditUser(string id)
        {
            var result = await _userService.GetUserByAsync(id);
            if (result.Success)
            {
                return View(result.Payload);
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditUser(EditUserVM model)
        {
            if (!User.IsInRole("Administrators"))
            {
                return RedirectToAction("Users", "Admin");
            }
            var validator = new EditUserValidation();
            var validationResult = await validator.ValidateAsync(model);
            if (validationResult.IsValid)
            {
                var result = await _userService.EditUserAsync(model);
                if (result.Success)
                {
                    return RedirectToAction("Users", "Admin");
                }

                ViewBag.AuthError = result.Message;
                return View(model);
            }
            return View(model);
        }

        public async Task<IActionResult> BanUser(string id)
        {
            var result = await _userService.BanUserAsync(id);
            if (result.Success)
            {
                return RedirectToAction("Users", "Admin");
            }
            return RedirectToAction("Users", "Admin");
        }

        public async Task<IActionResult> DeleteUser(string id)
        {
            var result = await _userService.DeleteUserAsync(id);
            if (result.Success)
            {
                return RedirectToAction("Users", "Admin");
            }
            return RedirectToAction("Users", "Admin");
        }
        #endregion
        #region Email
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var result = await _userService.ConfirmEmailAsync(userId, token);
            if (result.Success)
            {
                return RedirectToAction("ConfirmEmailPage", "Admin");
            }
            return View();
        }

        [AllowAnonymous]
        public IActionResult ConfirmEmailPage()
        {
            return View();
        }
        #endregion
        #region Categories

        
        #endregion
        #region Courses

        
        #endregion
    }
}
