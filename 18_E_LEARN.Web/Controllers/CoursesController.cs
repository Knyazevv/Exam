using _18_E_LEARN.BusinessLogic.Services;
using _18_E_LEARN.DataAccess.Data.Models.Categories;
using _18_E_LEARN.DataAccess.Data.ViewModels.Course;
using _18_E_LEARN.DataAccess.Validation.Course;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace _18_E_LEARN.Web.Controllers
{
    [Authorize]
    public class CoursesController : Controller
    {
        private readonly CourseService _courseService;
        private readonly CategoryService _categoryService;
        public CoursesController(CourseService courseService, CategoryService categoryService)
        {
            _courseService = courseService;
            _categoryService = categoryService;
        }
        public async Task<IActionResult> Index()
        {
            var result = await _courseService.GetAllAsync();
            return View(result.Payload);
        }

        public async Task<IActionResult> Add()
        {
            await LoadCategories();
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Add(AddCourseVM model)
        {
            var validator = new AddCourseValidation();
            var validationresult = await validator.ValidateAsync(model);
            if (validationresult.IsValid)
            {
                if (model.Files != null)
                {
                    model.Files = HttpContext.Request.Form.Files;
                }

                await _courseService.Create(model);
                return RedirectToAction(nameof(Index));
            }
            return View();
        }
        public async Task<IActionResult> Edit(int id)
        {
            var result = await _courseService.GetCourseByIdAsync(id);
            if (result.Success)
            {
                await LoadCategories();
                return View(result.Payload);
            }
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        public async Task<IActionResult> Edit(EditCourseVM model)
        {
            if (!User.IsInRole("Administrators"))
            {
                return RedirectToAction(nameof(Index));
            }
            var validator = new EditCourseValidation();
            var validationresult = await validator.ValidateAsync(model);
            if (validationresult.IsValid)
            {
                if (model.Files != null)
                {
                    model.Files = HttpContext.Request.Form.Files;
                }

                await _courseService.Update(model);
                return RedirectToAction(nameof(Index));
            }
            return View();
        }
        public async Task<IActionResult> Delete(int id)
        {
            var result = await _courseService.DeleteCourseByIdAsync(id);
            return RedirectToAction(nameof(Index));
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
    }
}
