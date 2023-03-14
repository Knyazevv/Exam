using _18_E_LEARN.BusinessLogic.Services;
using _18_E_LEARN.DataAccess.Data.Models.Categories;
using _18_E_LEARN.DataAccess.Data.ViewModels.Course;
using _18_E_LEARN.DataAccess.Validation.Course;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace _18_E_LEARN.Web.Controllers
{
    [Authorize]
    public class CategoryController : Controller
    {
        private readonly CategoryService _categoryService;
        public CategoryController(CategoryService categoryService)
        {
            _categoryService = categoryService;
        }
        public async Task<IActionResult> Index()
        {
            var result = await _categoryService.GetAllAsync();
            return View(result.Payload);
        }

        public IActionResult Add()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Add(AddCategoryVM model)
        {
            var validator = new AddCategoryValidation();
            var validationresult = await validator.ValidateAsync(model);
            if (validationresult.IsValid)
            {
                var result = await _categoryService.Create(model);
                if (result.Success)
                {
                    return RedirectToAction(nameof(Index));
                }
                ViewBag.Error = result.Message;
                return View();
            }
            return View();
        }

        public async Task<IActionResult> Edit(int Id)
        {
            var result = await _categoryService.GetByIdAsync(Id);
            return View(result.Payload);
        }

        [HttpPost]
        public async Task<IActionResult> Edit(Category model)
        {
            if (!User.IsInRole("Administrators"))
            {
                return RedirectToAction(nameof(Index));
            }
            var result = await _categoryService.Update(model);
            if (result.Success)
            {
                return RedirectToAction(nameof(Index));
            }
            ViewBag.Error = result.Message;
            return View();
        }
        public async Task<IActionResult> Delete(int id)
        {
            var result = await _categoryService.Delete(id);
            if (result.Success)
            {
                return RedirectToAction(nameof(Index));
            }
            ViewBag.Error = result.Message;
            return RedirectToAction(nameof(Index));
        }
    }
}
