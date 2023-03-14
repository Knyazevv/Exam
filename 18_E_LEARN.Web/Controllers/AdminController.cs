using _18_E_LEARN.BusinessLogic.Services;
using _18_E_LEARN.DataAccess.Data.Models.Categories;
using _18_E_LEARN.DataAccess.Data.Models.User;
using _18_E_LEARN.DataAccess.Data.ViewModels.Course;
using _18_E_LEARN.DataAccess.Data.ViewModels.User;
using _18_E_LEARN.DataAccess.Validation.Categories;
using _18_E_LEARN.DataAccess.Validation.Course;
using _18_E_LEARN.DataAccess.Validation.User;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Security.Claims;

namespace _18_E_LEARN.Web.Controllers
{
    [Authorize]
    public class AdminController : Controller
    {
        private readonly UserService _userService;
        private readonly CategoryService _categoryService;
        private readonly CourseService _courseService;
        private readonly IMapper _mapper;

        public AdminController(CourseService courseService, UserService userService, CategoryService categoryService, IMapper mapper)
        {
            _userService = userService;
            _categoryService = categoryService;
            _courseService = courseService;
            _mapper = mapper;
        }

        public IActionResult Index()
        {
            return View();
        }

        public  async Task<IActionResult> Users()
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

        public async Task<IActionResult> GetCategories()
        {
            var result = await _categoryService.GetAllAsync();
            return View(result.Payload);
        }

        public async Task<IActionResult> EditCategory(int Id)
        {
            var result = await _categoryService.GetByIdAsync(Id);
            return View(result.Payload);
        }



        [HttpPost]
        public async Task<IActionResult> EditCategory(Category model)
        {
            var result = await _categoryService.Update(model);
            if (result.Success)
            {
                return RedirectToAction(nameof(GetCategories));
            }
            ViewBag.Error = result.Message;
            return View();
        }

        public async Task<IActionResult> GetCourses()
        {
            var result = await _courseService.GetAllAsync();
            return View(result.Payload);
        }

        public async Task<IActionResult> AddCourse()
        {
            await LoadCategories();
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> AddCourse(AddCourseVM model)
        {
            var validator = new AddCourseValidation();
            var validationresult = await validator.ValidateAsync(model);
            if (validationresult.IsValid)
            {
                if(model.Files != null)
                {
                    model.Files = HttpContext.Request.Form.Files;
                }

                await _courseService.Create(model);
                return RedirectToAction(nameof(GetCourses));
            }
            return View();
        }

        private async Task LoadCategories()
        {
            var result = await _categoryService.GetAllAsync();
            ViewBag.CategoryList = new SelectList(
                (System.Collections.IEnumerable)result.Payload,
                nameof(Category.Id),
                nameof(Category.Name)
                );
        }





        [HttpPost]
        public async Task<IActionResult> DeleteCategory(Category model)
        {
            _categoryService.DeleteIdAsync(model.Id);
            return RedirectToAction("GetCategories", "Admin");

        }
        public async Task<IActionResult> AddCategory(int id)
        {
            var result = await _categoryService.GetByIdAsync(id);
            if (result.Success)
            {
                return View(result.Payload);
            }
            return View();
        }








        [HttpPost]
        public async Task<IActionResult> AddCategory(Category model)
        {
            var validator = new EditCategoryValidation();
            var validationResult = await validator.ValidateAsync(model);
            if (validationResult.IsValid)
            {
                _categoryService.AddCategoryAsync(model);
                return RedirectToAction("GetCategories", "Admin");
            }
            return View(model);
        }





    }
}
