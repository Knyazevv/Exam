using _18_E_LEARN.BusinessLogic.Services;
using _18_E_LEARN.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace _18_E_LEARN.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly CategoryService _categoryService;
        private readonly CourseService _courseService;

        public HomeController(ILogger<HomeController> logger, CourseService courseService, CategoryService categoryService)
        {
            _logger = logger;
            _categoryService = categoryService;
            _courseService = courseService;
        }

        public async Task<IActionResult> Index()
        {
            var result = await _courseService.GetAllAsync();
            return View(result.Payload);
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
    }
}